"""分析工具模块 - 提供二进制文件分析相关的 MCP 工具。

包含反编译、反汇编、函数列表、交叉引用、调用分析、字节搜索、
导入符号和全局变量等核心分析功能。
"""

from __future__ import annotations

import os
import re
from typing import Annotated, Any

from ..structured_facts import (
    normalize_batch_search_decompiled_patterns_result,
    normalize_extract_accesses_result,
    normalize_extract_carrier_facts_result,
    normalize_extract_function_facts_result,
    normalize_extract_lock_regions_result,
    normalize_extract_size_flow_facts_result,
    normalize_list_callsites_result,
)
from ..utils import normalize_list_input, parse_address
from . import register_tool


def _resolve_function(addr: str) -> tuple[int, str]:
    """Resolve an address/name to function start ea and function name."""
    import ida_funcs
    import ida_name

    ea = parse_address(addr)
    fn = ida_funcs.get_func(ea)
    start_ea = fn.start_ea if fn else ea
    name = ida_funcs.get_func_name(start_ea) or ida_name.get_name(start_ea) or str(addr)
    return start_ea, name


def _normalize_prototype_text(prototype: str, func_name: str) -> str:
    text = prototype.strip().rstrip(";")
    if func_name and "(" in text and func_name not in text:
        idx = text.find("(")
        prefix = text[:idx].rstrip()
        text = f"{prefix} {func_name}{text[idx:]}"
    return text


def _split_arguments(args_text: str) -> list[str]:
    """Split function arguments while keeping nested calls/types intact."""
    text = args_text.strip()
    if not text:
        return []
    if text == "void":
        return []

    parts: list[str] = []
    current: list[str] = []
    depth_paren = 0
    depth_angle = 0
    depth_bracket = 0

    for ch in text:
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren = max(0, depth_paren - 1)
        elif ch == "<":
            depth_angle += 1
        elif ch == ">":
            depth_angle = max(0, depth_angle - 1)
        elif ch == "[":
            depth_bracket += 1
        elif ch == "]":
            depth_bracket = max(0, depth_bracket - 1)

        if ch == "," and depth_paren == 0 and depth_angle == 0 and depth_bracket == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(ch)

    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_prototype_text(prototype: str) -> tuple[str | None, list[dict[str, Any]]]:
    """Parse return type and argument list from prototype text."""
    text = prototype.strip().rstrip(";")
    m = re.match(r"^(?P<ret>.+?)\s+(?P<name>[~\w:$<>]+)\s*\((?P<args>.*)\)$", text)
    if not m:
        return None, []

    ret_type = m.group("ret").strip()
    args_blob = m.group("args").strip()
    args = _split_arguments(args_blob)
    parsed_args: list[dict[str, Any]] = []

    for i, arg in enumerate(args):
        arg = arg.strip()
        if not arg:
            continue
        if arg == "...":
            parsed_args.append({"index": i, "name": "...", "type": "..."})
            continue

        name = f"arg{i}"
        arg_type = arg
        name_match = re.search(r"([A-Za-z_]\w*)(\s*(\[[^\]]+\])*)$", arg)
        if name_match:
            candidate = name_match.group(1)
            tail = name_match.group(2) or ""
            # Don't treat obvious C keywords as variable names.
            if candidate not in {
                "const",
                "volatile",
                "unsigned",
                "signed",
                "struct",
                "class",
            }:
                name = candidate
                type_prefix = arg[: name_match.start(1)].rstrip()
                arg_type = f"{type_prefix}{tail}".strip() if type_prefix else arg

        parsed_args.append(
            {
                "index": i,
                "name": name,
                "type": arg_type.strip(),
            }
        )

    return ret_type, parsed_args


def _extract_decl_type_and_name(decl: str) -> tuple[str | None, str | None]:
    text = decl.strip().rstrip(";")
    m = re.match(r"^(?P<type>.+?)\s+(?P<name>[A-Za-z_]\w*(?:\[[^\]]+\])*)$", text)
    if not m:
        return None, None
    return m.group("type").strip(), m.group("name").strip()


def _estimate_decl_size(type_name: str | None, var_name: str | None) -> int | None:
    """Estimate variable size from simple C declarations."""
    if not type_name:
        return None

    sizes = {
        "bool": 1,
        "char": 1,
        "signed char": 1,
        "unsigned char": 1,
        "uint8_t": 1,
        "int8_t": 1,
        "short": 2,
        "unsigned short": 2,
        "int16_t": 2,
        "uint16_t": 2,
        "int": 4,
        "unsigned int": 4,
        "long": 4,
        "unsigned long": 4,
        "int32_t": 4,
        "uint32_t": 4,
        "float": 4,
        "long long": 8,
        "unsigned long long": 8,
        "int64_t": 8,
        "uint64_t": 8,
        "double": 8,
    }

    base_type = " ".join(type_name.replace("*", " ").split()).strip()
    if "*" in type_name:
        base_size = None
    else:
        base_size = sizes.get(base_type)

    if var_name and "[" in var_name:
        dims = [int(x) for x in re.findall(r"\[(\d+)\]", var_name)]
        if dims:
            n = 1
            for dim in dims:
                n *= dim
            if base_size is not None:
                return base_size * n
            if base_type in {
                "char",
                "signed char",
                "unsigned char",
                "uint8_t",
                "int8_t",
            }:
                return n

    return base_size


def _format_stack_offset(offset: int | None) -> str | None:
    if offset is None:
        return None
    if offset >= 0:
        return f"[xsp+{offset:X}h]"
    return f"[xsp-{abs(offset):X}h]"


def _extract_stack_vars_from_lvars(cfunc: Any) -> list[dict]:
    """Best-effort extraction of stack locals from Hex-Rays lvars."""
    vars_out: list[dict] = []
    if not hasattr(cfunc, "get_lvars"):
        return vars_out

    try:
        lvars = cfunc.get_lvars()
    except Exception:
        return vars_out

    for lv in lvars or []:
        try:
            if hasattr(lv, "is_stk_var") and not lv.is_stk_var():
                continue
        except Exception:
            continue

        name = getattr(lv, "name", None)
        if callable(name):
            try:
                name = name()
            except Exception:
                name = None

        offset = None
        if hasattr(lv, "get_stkoff"):
            try:
                offset = int(lv.get_stkoff())
            except Exception:
                offset = None
        if offset is None and hasattr(lv, "location"):
            loc = getattr(lv, "location")
            if hasattr(loc, "stkoff"):
                try:
                    stkoff_attr = getattr(loc, "stkoff")
                    offset = int(
                        stkoff_attr() if callable(stkoff_attr) else stkoff_attr
                    )
                except Exception:
                    offset = None

        var_type = None
        size = None
        try:
            tinfo_obj = None
            if hasattr(lv, "type"):
                tinfo_attr = getattr(lv, "type")
                tinfo_obj = tinfo_attr() if callable(tinfo_attr) else tinfo_attr
            if tinfo_obj is not None:
                if hasattr(tinfo_obj, "_print"):
                    var_type = tinfo_obj._print()
                else:
                    var_type = str(tinfo_obj)
                if hasattr(tinfo_obj, "get_size"):
                    size = int(tinfo_obj.get_size())
        except Exception:
            pass

        if size is None:
            width = getattr(lv, "width", None)
            if callable(width):
                try:
                    width = width()
                except Exception:
                    width = None
            if isinstance(width, int) and width > 0:
                size = width

        vars_out.append(
            {
                "offset": offset,
                "offset_expr": _format_stack_offset(offset),
                "name": name or "<unnamed>",
                "type": var_type or "unknown",
                "size": size,
                "source": "lvars",
            }
        )

    vars_out.sort(
        key=lambda x: (
            x["offset"] is None,
            x["offset"] if x["offset"] is not None else 0,
        )
    )
    return vars_out


def _extract_stack_vars_from_code(code: str) -> list[dict]:
    """Fallback parser for stack locals from decompiled comments."""
    results: list[dict] = []
    seen: set[tuple[str | None, str | None]] = set()

    for line in code.splitlines():
        if "//" not in line:
            continue
        decl_part, comment_part = line.split("//", 1)
        decl_part = decl_part.strip()
        comment_part = comment_part.strip()
        if not decl_part.endswith(";"):
            continue

        match = re.search(
            r"\[(?P<base>xsp|rsp|esp|rbp|ebp)(?P<sign>[+-])(?P<off>[0-9A-Fa-f]+)h?\]",
            comment_part,
        )
        if not match:
            continue

        off = int(match.group("off"), 16)
        if match.group("sign") == "-":
            off = -off

        var_type, var_name = _extract_decl_type_and_name(decl_part)
        key = (var_name, _format_stack_offset(off))
        if key in seen:
            continue
        seen.add(key)

        results.append(
            {
                "offset": off,
                "offset_expr": _format_stack_offset(off),
                "name": var_name or "<unnamed>",
                "type": var_type or "unknown",
                "size": _estimate_decl_size(var_type, var_name),
                "source": "decompile_comment",
            }
        )

    results.sort(
        key=lambda x: (
            x["offset"] is None,
            x["offset"] if x["offset"] is not None else 0,
        )
    )
    return results


def _extract_call_candidates(code: str, callee_names: list[str]) -> list[dict]:
    """Extract potential call sites from pseudocode lines."""
    hits: list[dict] = []
    lines = code.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for callee in callee_names:
            for m in re.finditer(rf"(?<![A-Za-z_0-9]){re.escape(callee)}\s*\(", line):
                args_start = m.end()
                depth = 1
                i = args_start
                while i < len(line) and depth > 0:
                    ch = line[i]
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                    i += 1
                if depth != 0:
                    continue
                args_text = line[args_start : i - 1]
                hits.append(
                    {
                        "line_no": line_no,
                        "line_text": line.strip(),
                        "callee": callee,
                        "args": _split_arguments(args_text),
                    }
                )
    return hits


def _extract_assignment_chain(
    lines: list[str], start_line_no: int, expr: str, max_steps: int = 8
) -> list[dict]:
    """Trace variable assignments backward within one decompiled function."""
    chain: list[dict] = []
    current = expr.strip()
    var_match = re.match(r"^[A-Za-z_]\w*$", current)
    if not var_match:
        return chain

    for _ in range(max_steps):
        var_name = current
        found = False
        for i in range(start_line_no - 2, -1, -1):
            line = lines[i]
            m = re.search(rf"\b{re.escape(var_name)}\s*=\s*(?P<rhs>.+?);", line)
            if not m:
                continue
            rhs = m.group("rhs").strip()
            chain.append(
                {
                    "line_no": i + 1,
                    "var": var_name,
                    "expr": rhs,
                }
            )
            current = rhs
            found = True
            break

        if not found:
            break

        if not re.match(r"^[A-Za-z_]\w*$", current):
            break

    return chain


def _line_and_context(text: str, index: int, radius: int = 80) -> tuple[int, str, str]:
    line_no = text.count("\n", 0, index) + 1
    line_start = text.rfind("\n", 0, index)
    line_end = text.find("\n", index)
    if line_start < 0:
        line_start = 0
    else:
        line_start += 1
    if line_end < 0:
        line_end = len(text)

    line_text = text[line_start:line_end].strip()
    snippet_start = max(0, index - radius)
    snippet_end = min(len(text), index + radius)
    snippet = text[snippet_start:snippet_end].replace("\n", " ").strip()
    return line_no, line_text, snippet


_DEFAULT_DECOMPILED_SEARCH_FUNCTION_CAP = 50
_DECOMPILED_SEARCH_FUNCTION_CAP_ENV = "AI4BA_IDA_DECOMPILED_SEARCH_FUNCTION_CAP"


def _decompiled_search_function_cap() -> int:
    try:
        value = int(
            str(os.environ.get(_DECOMPILED_SEARCH_FUNCTION_CAP_ENV) or "").strip()
        )
    except ValueError:
        value = 0
    return value if value > 0 else _DEFAULT_DECOMPILED_SEARCH_FUNCTION_CAP


def _resolve_decompiled_search_limit(
    max_functions: Any,
) -> tuple[int, dict[str, Any] | None]:
    try:
        requested = int(max_functions)
    except (TypeError, ValueError):
        requested = _DEFAULT_DECOMPILED_SEARCH_FUNCTION_CAP

    cap = _decompiled_search_function_cap()
    if requested <= 0:
        return 0, {
            "code": "max-functions-zero-blocked",
            "message": (
                "max_functions=0 is disabled for decompiled-code search; "
                f"retry with selected_functions or max_functions<={cap}"
            ),
            "requested_max_functions": requested,
            "max_functions_cap": cap,
        }

    effective = min(requested, cap)
    return effective, {
        "requested_max_functions": requested,
        "effective_max_functions": effective,
        "max_functions_cap": cap,
        "capped": requested > effective,
    }


def _prepare_decompiled_pattern_specs(
    patterns: Any,
    *,
    case_sensitive: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Compile planned batch-search pattern specs without binding them to a vuln profile."""
    diagnostics: list[dict[str, str]] = []
    compiled: list[dict[str, Any]] = []
    flags = re.MULTILINE if case_sensitive else re.MULTILINE | re.IGNORECASE

    for index, item in enumerate(normalize_list_input(patterns)):
        if isinstance(item, dict):
            pattern_id = str(
                item.get("id") or item.get("pattern_id") or f"pattern-{index}"
            )
            regex_text = str(item.get("regex") or item.get("pattern") or "")
        else:
            pattern_id = f"pattern-{index}"
            regex_text = str(item)

        if not regex_text:
            diagnostics.append(
                {
                    "code": "empty-regex",
                    "message": f"Pattern {pattern_id} has no regex",
                }
            )
            continue

        try:
            regex = re.compile(regex_text, flags)
        except re.error as exc:
            diagnostics.append(
                {
                    "code": "invalid-regex",
                    "message": f"Pattern {pattern_id} failed to compile: {exc}",
                }
            )
            continue

        compiled.append(
            {
                "id": pattern_id,
                "regex": regex_text,
                "compiled": regex,
            }
        )

    return compiled, diagnostics


_CONTROL_CALL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "sizeof",
    "return",
    "catch",
}


def _matching_paren_index(text: str, open_index: int) -> int | None:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _callee_from_prefix(prefix: str) -> str:
    end = len(prefix.rstrip())
    if end <= 0:
        return ""
    index = end - 1
    angle_depth = 0
    while index >= 0:
        char = prefix[index]
        if char == ">":
            angle_depth += 1
        elif char == "<":
            angle_depth = max(0, angle_depth - 1)

        if char.isspace() and angle_depth == 0:
            break
        if char.isalnum() or char in "_:~.-><*&[] ":
            index -= 1
            continue
        break
    return prefix[index + 1 : end].strip()


def _callee_display_parts(callee_expr: str) -> tuple[str, str]:
    text = " ".join(callee_expr.strip().split())
    if not text:
        return "", ""
    for separator in ("->", "."):
        if separator in text:
            return text, text.rsplit(separator, 1)[-1].strip()
    if "::" in text:
        return text, text.rsplit("::", 1)[-1].strip()
    return text, text


def _call_kind_for_callee(callee_expr: str) -> str:
    callee = callee_expr.strip()
    if callee.startswith("operator") or "::operator" in callee:
        return "operator"
    if "->" in callee or "." in callee or "::" in callee:
        return "method"
    return "call"


def _target_kind_for_callee(callee_expr: str, callee_ea: str | None = None) -> str:
    lowered = callee_expr.strip().lower()
    if lowered.startswith(("__imp_", "imp_")) or "::__imp_" in lowered:
        return "import"
    if lowered.startswith(("j_", "thunk_")) or "thunk" in lowered:
        return "thunk"
    if "(*" in lowered or "->*" in lowered:
        return "indirect"
    if "vtable" in lowered or "vftable" in lowered:
        return "vtable"
    if callee_ea is not None or callee_expr:
        return "direct"
    return "unknown"


def _canonical_call_name(value: str) -> str:
    text = value.strip().lower().lstrip(".")
    text = re.sub(r"^_+imp_?", "", text)
    text = re.sub(r"^j_", "", text)
    text = re.sub(r"[^a-z0-9_]+", "", text)
    return text


def _call_names_match(decompiled_name: str, disasm_name: str) -> bool:
    left = _canonical_call_name(decompiled_name)
    right = _canonical_call_name(disasm_name)
    if not left or not right:
        return False
    return left == right or left in right or right in left


def _find_matching_disasm_call(
    call: dict[str, Any],
    disasm_calls: list[dict[str, Any]],
    used_disasm_indexes: set[int],
) -> dict[str, Any]:
    for index, disasm in enumerate(disasm_calls):
        if index in used_disasm_indexes:
            continue
        if _call_names_match(call["callee_name"], str(disasm.get("callee_name") or "")):
            used_disasm_indexes.add(index)
            return disasm
    return {}


def _looks_like_multiline_call_start(line: str) -> bool:
    stripped = line.strip()
    if not stripped or ";" in stripped:
        return False
    if stripped.endswith("{") or stripped.startswith(
        ("if ", "for ", "while ", "switch ")
    ):
        return False
    lowered = stripped.lower()
    return "(" in stripped and (
        stripped.lstrip().startswith("*")
        or "std::" in stripped
        or "operator" in lowered
        or "->" in stripped
        or "." in stripped
    )


def _iter_decompiled_statements(code: str) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    pending: list[str] = []
    pending_line = 0
    for line_no, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if pending:
            if "{" in stripped and ";" not in stripped:
                pending = []
                pending_line = 0
                continue
            pending.append(stripped)
            if ";" in stripped:
                statements.append(
                    {
                        "line_no": pending_line,
                        "line_text": " ".join(part for part in pending if part).strip(),
                    }
                )
                pending = []
                pending_line = 0
            continue

        if not stripped:
            continue
        if ";" in stripped:
            statements.append({"line_no": line_no, "line_text": stripped})
            continue
        if _looks_like_multiline_call_start(stripped):
            pending = [stripped]
            pending_line = line_no
    return statements


def _iter_pseudocode_calls(code: str) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for statement in _iter_decompiled_statements(code):
        line_no = int(statement["line_no"])
        line = str(statement["line_text"])
        # Skip function prototypes and block headers.  Calls that matter for
        # these tools should have a statement terminator in Hex-Rays output.
        if ";" not in line:
            continue
        search_from = 0
        while True:
            open_index = line.find("(", search_from)
            if open_index < 0:
                break
            close_index = _matching_paren_index(line, open_index)
            if close_index is None:
                break

            callee_expr = _callee_from_prefix(line[:open_index])
            full_callee, callee_name = _callee_display_parts(callee_expr)
            if not callee_name or callee_name in _CONTROL_CALL_KEYWORDS:
                search_from = open_index + 1
                continue

            args_text = line[open_index + 1 : close_index]
            calls.append(
                {
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "callee_expr": full_callee,
                    "callee_name": callee_name,
                    "args": _split_arguments(args_text),
                    "call_kind": _call_kind_for_callee(full_callee),
                    "target_kind": _target_kind_for_callee(full_callee),
                }
            )
            search_from = close_index + 1
    return calls


def _disassembly_call_facts(func_start: int) -> list[dict[str, Any]]:
    """Best-effort call instruction facts for source refs and target classification."""
    facts: list[dict[str, Any]] = []
    try:
        import ida_funcs
        import ida_idp
        import ida_name
        import ida_ua
        import idaapi

        func = (
            idaapi.get_func(func_start)
            if hasattr(idaapi, "get_func")
            else ida_funcs.get_func(func_start)
        )
        if not func:
            return facts

        current_ea = func.start_ea
        while current_ea < func.end_ea:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, current_ea)
            if length <= 0:
                next_ea = idaapi.next_head(current_ea, func.end_ea)
                if next_ea == idaapi.BADADDR:
                    break
                current_ea = next_ea
                continue

            if ida_idp.is_call_insn(insn):
                target = None
                if getattr(insn, "ops", None):
                    op0 = insn.ops[0]
                    if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                        target = op0.addr
                    elif op0.type == ida_ua.o_imm:
                        target = op0.value
                target_name = ida_name.get_name(target) if target is not None else ""
                facts.append(
                    {
                        "callsite_ea": hex(current_ea),
                        "callee_ea": hex(target) if target is not None else None,
                        "callee_name": target_name or "",
                        "target_kind": _target_kind_for_callee(
                            target_name or "",
                            hex(target) if target is not None else None,
                        ),
                        "source_refs": {
                            "source": "disasm",
                            "disasm_operand": hex(current_ea),
                        },
                    }
                )

            next_ea = idaapi.next_head(current_ea, func.end_ea)
            if next_ea == idaapi.BADADDR:
                break
            current_ea = next_ea
    except Exception:
        return facts
    return facts


def _matches_callee_filter(
    callee_expr: str, callee_name: str, callee_filter: str
) -> bool:
    if not callee_filter or callee_filter == "*":
        return True
    import fnmatch

    return fnmatch.fnmatch(callee_expr, callee_filter) or fnmatch.fnmatch(
        callee_name, callee_filter
    )


def _list_callsites_from_decompiled_code(
    *,
    function_ea: int,
    function_name: str,
    code: str,
    callee_filter: str,
    include_args: bool,
    max_calls: int,
) -> list[dict[str, Any]]:
    disasm_calls = _disassembly_call_facts(function_ea)
    parsed_calls = [
        call
        for call in _iter_pseudocode_calls(code)
        if _matches_callee_filter(
            call["callee_expr"], call["callee_name"], callee_filter
        )
    ]
    if max_calls > 0:
        parsed_calls = parsed_calls[:max_calls]

    output: list[dict[str, Any]] = []
    used_disasm_indexes: set[int] = set()
    for index, call in enumerate(parsed_calls):
        disasm = _find_matching_disasm_call(call, disasm_calls, used_disasm_indexes)
        target_kind = disasm.get("target_kind") or call["target_kind"]
        callee_name = disasm.get("callee_name") or call["callee_name"]
        callee_ea = disasm.get("callee_ea")
        source_refs = {
            "source": "decompile",
            "function_ea": hex(function_ea),
            "line_no": call["line_no"],
        }
        if disasm.get("source_refs"):
            source_refs["disasm"] = disasm["source_refs"]
        output.append(
            {
                "callsite_ea": disasm.get("callsite_ea"),
                "function_ea": hex(function_ea),
                "function_name": function_name,
                "callee_ea": callee_ea,
                "callee_name": callee_name,
                "target_kind": target_kind,
                "call_kind": call["call_kind"],
                "args": call["args"] if include_args else [],
                "line_no": call["line_no"],
                "line_text": call["line_text"],
                "raw_name": callee_name,
                "source_refs": source_refs,
                "confidence": 0.9 if disasm else 0.65,
                "partial": not bool(disasm),
                "unavailable_reason": "" if disasm else "callsite-ea-unavailable",
            }
        )
    return output


def _access_mode_for_expr(line: str, expr: str) -> str:
    assignment = re.search(r"(?<![=!<>])=(?!=)", line)
    if not assignment:
        return "read"
    expr_index = line.find(expr)
    if expr_index >= 0 and expr_index < assignment.start():
        return "write"
    return "read"


def _access_kind_enabled(kind: str, filters: dict[str, Any] | None) -> bool:
    filters = filters or {}
    if kind in {"global"} and filters.get("include_globals") is False:
        return False
    if kind in {"member"} and filters.get("include_members") is False:
        return False
    if (
        kind in {"container", "container-index", "handle-map"}
        and filters.get("include_containers") is False
    ):
        return False
    return True


def _access_symbol_matches(
    base: str, expr: str, filters: dict[str, Any] | None
) -> bool:
    symbols = normalize_list_input((filters or {}).get("symbols", []))
    if not symbols:
        return True
    import fnmatch

    return any(
        fnmatch.fnmatch(base, str(symbol))
        or fnmatch.fnmatch(expr, str(symbol))
        or str(symbol) in expr
        for symbol in symbols
    )


def _with_access_site_eas(
    function_ea: int, accesses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    disasm_eas: list[str] = []
    try:
        import ida_ua
        import idaapi

        func = idaapi.get_func(function_ea)
        if func:
            ea = func.start_ea
            while ea < func.end_ea:
                insn = ida_ua.insn_t()
                length = ida_ua.decode_insn(insn, ea)
                if length > 0:
                    disasm_eas.append(hex(ea))
                next_ea = idaapi.next_head(ea, func.end_ea)
                if next_ea == idaapi.BADADDR:
                    break
                ea = next_ea
    except Exception:
        disasm_eas = []

    for access in accesses:
        line_no = access.get("line_no")
        if isinstance(line_no, int) and 0 < line_no <= len(disasm_eas):
            access["site_ea"] = disasm_eas[line_no - 1]
            access["partial"] = False
            access["unavailable_reason"] = ""
            refs = access.setdefault("source_refs", {})
            refs["disasm_operand"] = access["site_ea"]
    return accesses


def _extract_access_facts_from_code(
    function_ea: int, code: str
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    for line_no, line in enumerate(code.splitlines(), start=1):
        for match in re.finditer(
            r"\b(?P<base>[A-Za-z_]\w*)\s*\[(?P<index>[^\]]+)\]", line
        ):
            expr = match.group(0)
            key = (line_no, expr, "container-index")
            if key in seen:
                continue
            seen.add(key)
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "expr": expr,
                    "base": match.group("base"),
                    "kind": "container-index",
                    "access": _access_mode_for_expr(line, expr),
                    "index_expr": match.group("index").strip(),
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.65,
                    "partial": True,
                    "unavailable_reason": "site-ea-unavailable",
                }
            )

        for match in re.finditer(
            r"\b(?P<base>this|[A-Za-z_]\w*)\s*(?P<op>->|\.)\s*(?P<field>[A-Za-z_]\w*)",
            line,
        ):
            expr = match.group(0)
            if line[match.end() :].lstrip().startswith("("):
                continue
            key = (line_no, expr, "member")
            if key in seen:
                continue
            seen.add(key)
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "expr": expr,
                    "base": match.group("field"),
                    "kind": "member",
                    "access": _access_mode_for_expr(line, expr),
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.55,
                    "partial": True,
                    "unavailable_reason": "site-ea-unavailable",
                }
            )

        for match in re.finditer(r"\bg_[A-Za-z_]\w*\b", line):
            expr = match.group(0)
            key = (line_no, expr, "global")
            if key in seen:
                continue
            seen.add(key)
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "expr": expr,
                    "base": expr,
                    "kind": "global",
                    "access": _access_mode_for_expr(line, expr),
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.5,
                    "partial": True,
                    "unavailable_reason": "site-ea-unavailable",
                }
            )
    return facts


def _filter_access_facts(
    accesses: list[dict[str, Any]], filters: dict[str, Any] | None
) -> list[dict[str, Any]]:
    filtered = []
    for access in accesses:
        kind = str(access.get("kind") or access.get("access_kind") or "unknown")
        base = str(access.get("base") or "")
        expr = str(access.get("expr") or "")
        if not _access_kind_enabled(kind, filters):
            continue
        if not _access_symbol_matches(base, expr, filters):
            continue
        filtered.append(access)
    return filtered


def _extract_assignment_facts_from_code(
    function_ea: int, code: str
) -> list[dict[str, Any]]:
    assignments: list[dict[str, Any]] = []
    for statement in _iter_decompiled_statements(code):
        line_no = int(statement["line_no"])
        line = str(statement["line_text"])
        map_store = re.search(
            r"\*?\s*(?P<callee>.*?operator\[\]\s*\((?P<args>.*?)\))\s*=\s*(?P<rhs>[^;]+);",
            line,
            re.DOTALL,
        )
        if map_store:
            args = _split_arguments(map_store.group("args"))
            base_expr = (
                args[0].strip().lstrip("&")
                if args
                else map_store.group("callee").strip()
            )
            key_expr = args[1].strip().lstrip("&") if len(args) > 1 else ""
            lhs = f"{base_expr}[{key_expr}]" if key_expr else base_expr
            assignments.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "line_no": line_no,
                    "lhs": lhs,
                    "rhs": map_store.group("rhs").strip(),
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.65,
                    "partial": True,
                    "unavailable_reason": "multiline-operator-assignment",
                }
            )
            continue
        match = re.search(
            r"(?P<lhs>[^;=!<>]+?)\s*(?<![=!<>])=(?!=)\s*(?P<rhs>[^;]+);", line
        )
        if not match:
            continue
        assignments.append(
            {
                "function_ea": hex(function_ea),
                "site_ea": _site_ea_for_line(function_ea, line_no),
                "line_no": line_no,
                "lhs": match.group("lhs").strip(),
                "rhs": match.group("rhs").strip(),
                "line_text": line.strip(),
                "source_refs": {
                    "source": "decompile",
                    "function_ea": hex(function_ea),
                    "line_no": line_no,
                },
                "confidence": 0.75,
                "partial": False,
                "unavailable_reason": "",
            }
        )
    return assignments


def _extract_invalidation_facts_from_code(
    function_ea: int, code: str
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for statement in _iter_decompiled_statements(code):
        line_no = int(statement["line_no"])
        line = str(statement["line_text"])
        lowered = line.lower()
        if not any(
            token in lowered for token in ("erase", "clear", "unregister", "remove")
        ):
            continue
        match = re.search(
            r"(?P<callee>[A-Za-z_:~<> ,`'()*]+(?:erase|clear|unregister|remove)[A-Za-z_:~<> ,`'()*]*)\s*\((?P<args>.*?)\)",
            line,
            re.IGNORECASE | re.DOTALL,
        )
        if not match:
            continue
        args = _split_arguments(match.group("args"))
        callee = match.group("callee").strip()
        facts.append(
            {
                "site_ea": _site_ea_for_line(function_ea, line_no),
                "function_ea": hex(function_ea),
                "kind": callee,
                "target": args[0].strip() if args else "",
                "expr": line.strip(),
                "line_text": line.strip(),
                "source_refs": {
                    "source": "decompile",
                    "function_ea": hex(function_ea),
                    "line_no": line_no,
                },
                "confidence": 0.6,
                "partial": True,
                "unavailable_reason": "multiline-invalidation-call",
            }
        )
    return facts


def _extract_invalidation_facts_from_calls(
    callsites: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    invalidation_names = {
        "clear",
        "reset",
        "erase",
        "release",
        "free",
        "delete",
        "close",
        "destroy",
        "unregister",
        "clean",
        "cleancache",
    }
    facts: list[dict[str, Any]] = []
    for call in callsites:
        callee_name = str(call.get("callee_name") or "")
        normalized = callee_name.lower().replace("_", "")
        if normalized not in invalidation_names and not any(
            normalized.endswith(name) for name in invalidation_names
        ):
            continue
        args = call.get("args") or []
        first_arg = ""
        if args:
            first_arg_value = args[0]
            if isinstance(first_arg_value, dict):
                first_arg = str(first_arg_value.get("expr") or "")
            else:
                first_arg = str(first_arg_value)
        facts.append(
            {
                "site_ea": call.get("callsite_ea"),
                "function_ea": call.get("function_ea"),
                "kind": callee_name or "unknown",
                "target": first_arg,
                "expr": call.get("line_text", ""),
                "line_text": call.get("line_text", ""),
                "source_refs": call.get("source_refs", {}),
                "confidence": call.get("confidence", 0.5),
                "partial": call.get("partial", False),
                "unavailable_reason": call.get("unavailable_reason", ""),
            }
        )
    return facts


def _extract_lock_facts_from_code(function_ea: int, code: str) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    lock_patterns = [
        (
            r"\b(?:std::)?(?:unique_lock|lock_guard|scoped_lock)\s*<[^>]*>\s*(?P<name>[A-Za-z_]\w*)?\s*\((?P<arg>[^)]*)\)",
            "raii-lock",
        ),
        (r"\b(?:pthread_mutex_lock|mutex_lock)\s*\((?P<arg>[^)]*)\)", "explicit-lock"),
        (r"(?P<arg>[A-Za-z_]\w*)\s*(?:->|\.)\s*lock\s*\(", "method-lock"),
        (r"(?P<arg>[A-Za-z_]\w*)\s*(?:->|\.)\s*unlock\s*\(", "method-unlock"),
    ]
    for line_no, line in enumerate(code.splitlines(), start=1):
        for pattern, kind in lock_patterns:
            match = re.search(pattern, line)
            if not match:
                continue
            lock_name = (
                match.groupdict().get("arg") or match.groupdict().get("name") or ""
            ).strip()
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "lock_name": lock_name,
                    "lock_kind": kind,
                    "start_line": line_no,
                    "end_line": None,
                    "unlock_kind": "unknown",
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.55,
                    "partial": True,
                    "unavailable_reason": "site-ea-unavailable",
                }
            )
            break
    return facts


def _normalize_lock_expr(expr: str) -> str:
    text = expr.strip()
    text = text.lstrip("&")
    text = text.replace("this->", "")
    return " ".join(text.split())


def _extract_lock_regions_from_code(
    function_ea: int,
    code: str,
    *,
    lock_names: list[str] | None = None,
    lock_api_patterns: list[str] | None = None,
    accesses: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    lock_names = [
        _normalize_lock_expr(name) for name in (lock_names or []) if str(name).strip()
    ]
    lock_api_patterns = [
        str(item) for item in (lock_api_patterns or []) if str(item).strip()
    ]
    access_facts = accesses or []
    lines = code.splitlines()
    regions: list[dict[str, Any]] = []

    def _api_allowed(line: str) -> bool:
        if not lock_api_patterns:
            return True
        return any(re.search(pattern, line) for pattern in lock_api_patterns)

    def _lock_allowed(lock_name: str) -> bool:
        if not lock_names:
            return True
        return any(
            lock_name == item or item in lock_name or lock_name in item
            for item in lock_names
        )

    for line_no, line in enumerate(lines, start=1):
        candidates: list[tuple[str, str, str]] = []
        for pattern, kind in [
            (
                r"\b(?:std::)?(?:unique_lock|lock_guard|scoped_lock)\s*<[^>]*>\s*(?P<name>[A-Za-z_]\w*)?\s*\((?P<arg>[^)]*)\)",
                "raii-lock",
            ),
            (
                r"\b(?:pthread_mutex_lock|mutex_lock)\s*\((?P<arg>[^)]*)\)",
                "explicit-lock",
            ),
            (r"(?P<arg>[A-Za-z_]\w*)\s*(?:->|\.)\s*lock\s*\(", "method-lock"),
        ]:
            match = re.search(pattern, line)
            if not match:
                continue
            arg = _normalize_lock_expr(
                match.groupdict().get("arg") or match.groupdict().get("name") or ""
            )
            candidates.append((arg, kind, line.strip()))

        for lock_name, kind, line_text in candidates:
            if not _api_allowed(line_text) or not _lock_allowed(lock_name):
                continue

            end_line = len(lines)
            unlock_kind = "scope"
            if kind in {"explicit-lock", "method-lock"}:
                for unlock_line_no in range(line_no + 1, len(lines) + 1):
                    unlock_line = lines[unlock_line_no - 1]
                    if re.search(
                        r"\b(?:pthread_mutex_unlock|mutex_unlock)\s*\(", unlock_line
                    ) or re.search(r"\bunlock\s*\(", unlock_line):
                        end_line = unlock_line_no
                        unlock_kind = "explicit"
                        break

            covered = [
                access
                for access in access_facts
                if isinstance(access.get("line_no"), int)
                and line_no <= access["line_no"] <= end_line
            ]
            regions.append(
                {
                    "function_ea": hex(function_ea),
                    "lock_name": lock_name,
                    "lock_key": lock_name,
                    "lock_kind": kind,
                    "start_line": line_no,
                    "end_line": end_line,
                    "unlock_kind": unlock_kind,
                    "covered_accesses": covered,
                    "covered_site_eas": [
                        item.get("site_ea") for item in covered if item.get("site_ea")
                    ],
                    "line_text": line_text,
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.65 if end_line else 0.5,
                    "partial": True,
                    "unavailable_reason": "site-ea-unavailable",
                }
            )
    return regions


def _carrier_kind_from_access(access: dict[str, Any]) -> str:
    base = str(access.get("base") or "")
    kind = str(access.get("kind") or access.get("access_kind") or "unknown")
    if kind == "container-index" and base.startswith(("g_", "s_")):
        return "global-static-registry"
    if kind == "container-index":
        return "container"
    if kind == "global":
        return "global-slot"
    if kind == "member":
        return "member-field"
    return kind or "unknown"


def _extract_aliases_for_carrier(
    carrier_key: str, assignments: list[dict[str, Any]]
) -> list[str]:
    aliases: set[str] = set()
    for assignment in assignments:
        lhs = str(assignment.get("lhs") or "")
        rhs = str(assignment.get("rhs") or "")
        if carrier_key not in rhs and carrier_key not in lhs:
            continue
        if carrier_key in rhs:
            alias = lhs.split()[-1].strip("*&")
            if alias and alias != carrier_key:
                aliases.add(alias)
        if carrier_key in lhs:
            alias = rhs.split()[-1].strip("*&")
            if alias and alias != carrier_key:
                aliases.add(alias)
    return sorted(aliases)


def _aggregate_carrier_facts(
    *,
    function_ea: int,
    accesses: list[dict[str, Any]],
    invalidations: list[dict[str, Any]],
    assignments: list[dict[str, Any]],
    locks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    carriers_by_key: dict[str, dict[str, Any]] = {}
    for access in accesses:
        key = str(access.get("base") or access.get("expr") or "")
        if not key:
            continue
        carrier = carriers_by_key.setdefault(
            key,
            {
                "key": key,
                "kind": _carrier_kind_from_access(access),
                "function_ea": hex(function_ea),
                "accesses": [],
                "invalidations": [],
                "aliases": [],
                "locks": [],
                "site_eas": [],
                "source_refs": {"source": "decompile", "function_ea": hex(function_ea)},
                "confidence": 0.65,
                "partial": True,
                "unavailable_reason": "site-ea-unavailable",
            },
        )
        carrier["accesses"].append(access)
        if access.get("site_ea"):
            carrier["site_eas"].append(access["site_ea"])

    for key, carrier in carriers_by_key.items():
        carrier["aliases"] = _extract_aliases_for_carrier(key, assignments)
        for invalidation in invalidations:
            target = str(invalidation.get("target") or "")
            expr = str(invalidation.get("expr") or invalidation.get("line_text") or "")
            if key and (key in target or key in expr):
                carrier["invalidations"].append(invalidation)
        for lock in locks:
            covered = lock.get("covered_accesses") or []
            if any(str(access.get("base") or "") == key for access in covered):
                carrier["locks"].append(lock)
        if carrier["invalidations"] or carrier["aliases"]:
            carrier["confidence"] = 0.75
    return list(carriers_by_key.values())


def _function_fact_hints(accesses: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    globals_out = sorted(
        {
            item.get("base", "")
            for item in accesses
            if item.get("access_kind") == "global" or item.get("kind") == "global"
        }
    )
    members_out = sorted(
        {
            item.get("base", "")
            for item in accesses
            if item.get("access_kind") == "member" or item.get("kind") == "member"
        }
    )
    return [item for item in globals_out if item], [
        item for item in members_out if item
    ]


_SIZE_NAME_RE = re.compile(
    r"(?:^|_)(?:len|length|size|count|capacity|cap|limit|bound|bytes?|n)(?:_|$)",
    re.IGNORECASE,
)


def _is_size_like_name(name: str) -> bool:
    text = name.strip()
    if not text:
        return False
    if _SIZE_NAME_RE.search(text):
        return True
    return text.lower() in {"n", "sz", "cnt", "cap"}


def _is_pointer_like_name(name: str) -> bool:
    text = re.sub(r"\s+", "", str(name or "")).lower()
    if not text:
        return False
    return bool(
        re.search(r"(?:buf|buffer|ptr|mem|dst|dest|out|data|base|curr|current)", text)
    )


def _callee_likely_nonallocator(callee: str) -> bool:
    text = str(callee or "").lower().split("::")[-1]
    return any(
        token in text
        for token in (
            "read",
            "write",
            "parse",
            "decode",
            "log",
            "print",
            "free",
            "release",
        )
    )


def _width_signedness_from_type(type_text: str) -> tuple[int | None, str]:
    text = type_text.lower()
    if (
        "size_t" in text
        or "uint64" in text
        or "uintptr" in text
        or "__int64" in text
        or "unsigned long" in text
    ):
        return 64, (
            "unsigned"
            if "unsigned" in text or "size_t" in text or "uint" in text
            else "signed"
        )
    if "uint32" in text or "dword" in text or "unsigned int" in text:
        return 32, "unsigned"
    if "int32" in text or "int " in f"{text} ":
        return 32, "signed"
    if "uint16" in text or "word" in text:
        return 16, "unsigned"
    if "int16" in text:
        return 16, "signed"
    if "uint8" in text or "byte" in text or "unsigned char" in text:
        return 8, "unsigned"
    if "char" in text:
        return 8, "unknown"
    return None, "unknown"


def _extract_signature_line(code: str, function_name: str) -> str:
    for line in code.splitlines()[:8]:
        stripped = line.strip()
        if (
            "(" in stripped
            and ")" in stripped
            and not stripped.startswith(("if ", "for ", "while ", "switch "))
        ):
            if function_name and function_name in stripped:
                return stripped.rstrip("{").strip()
            if re.search(r"\b[A-Za-z_]\w*\s*\(", stripped):
                return stripped.rstrip("{").strip()
    return ""


def _extract_function_arg_size_sources(
    function_ea: int, function_name: str, code: str
) -> list[dict[str, Any]]:
    signature = _extract_signature_line(code, function_name)
    if not signature or "(" not in signature or ")" not in signature:
        return []
    args_blob = signature[signature.find("(") + 1 : signature.rfind(")")]
    facts: list[dict[str, Any]] = []
    for arg in _split_arguments(args_blob):
        parsed = _parse_prototype_text(f"void f({arg})")[1]
        if not parsed:
            continue
        name = str(parsed[0].get("name") or "")
        type_text = str(parsed[0].get("type") or "")
        if (
            not _is_size_like_name(name)
            and "size_t" not in type_text.lower()
            and not re.search(r"\b(?:len|size|count)\b", type_text, re.I)
        ):
            continue
        width_bits, signedness = _width_signedness_from_type(type_text)
        facts.append(
            {
                "function_ea": hex(function_ea),
                "source_ea": hex(function_ea),
                "site_ea": hex(function_ea),
                "source_kind": "function-arg",
                "size_expr": name,
                "width_bits": width_bits,
                "signedness": signedness,
                "trust_boundary": "unknown",
                "line_no": 1,
                "line_text": signature,
                "source_refs": {
                    "source": "decompile-signature",
                    "function_ea": hex(function_ea),
                    "argument": name,
                },
                "confidence": 0.6,
                "partial": False,
            }
        )
    return facts


def _site_ea_for_line(function_ea: int, line_no: int) -> str:
    return hex(function_ea + max(0, line_no - 1))


def _out_param_name_from_reader_arg(
    arg: str, *, allow_plain_identifier: bool = False
) -> str:
    text = str(arg or "").strip()
    if not text:
        return ""
    has_address = "&" in text
    # Preserve the final identifier while ignoring common decompiler casts.
    stripped = re.sub(r"\([^)]*\)", " ", text)
    stripped = stripped.replace("&", " ").replace("*", " ")
    tokens = _extract_identifier_tokens(stripped)
    if not tokens:
        return ""
    candidate = tokens[-1]
    if candidate.lower() in {"this", "nullptr", "null"}:
        return ""
    if has_address or allow_plain_identifier:
        return candidate
    return ""


def _size_source_from_reader_call(
    function_ea: int, line_no: int, line: str
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for match in re.finditer(
        r"(?P<callee>[A-Za-z_]\w*(?:read|Read|get|Get|parse|Parse)[A-Za-z_]\w*)\s*\((?P<args>[^;]*)\)",
        line,
    ):
        args = _split_arguments(match.group("args"))
        callee = match.group("callee")
        width_bits = None
        for arg in args:
            literal = _parse_int_literal(arg)
            if literal in {1, 2, 3, 4, 5, 8, 9, 16, 24, 32, 64}:
                width_bits = literal
                break
        for arg in args:
            out = _out_param_name_from_reader_arg(arg)
            if not out:
                continue
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "source_ea": _site_ea_for_line(function_ea, line_no),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "source_kind": "cursor-read",
                    "size_expr": out,
                    "width_bits": width_bits,
                    "signedness": "unsigned" if width_bits else "unknown",
                    "trust_boundary": "unknown",
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                        "callee": callee,
                    },
                    "confidence": 0.55,
                    "partial": True,
                    "unavailable_reason": "trust-boundary-unknown",
                }
            )
        if width_bits and len(args) >= 3:
            out = _out_param_name_from_reader_arg(args[-1], allow_plain_identifier=True)
            if out and not any(fact.get("size_expr") == out for fact in facts):
                facts.append(
                    {
                        "function_ea": hex(function_ea),
                        "source_ea": _site_ea_for_line(function_ea, line_no),
                        "site_ea": _site_ea_for_line(function_ea, line_no),
                        "source_kind": "cursor-read",
                        "size_expr": out,
                        "width_bits": width_bits,
                        "signedness": "unsigned",
                        "trust_boundary": "unknown",
                        "line_no": line_no,
                        "line_text": line.strip(),
                        "source_refs": {
                            "source": "decompile",
                            "function_ea": hex(function_ea),
                            "line_no": line_no,
                            "callee": callee,
                        },
                        "confidence": 0.4,
                        "partial": True,
                        "unavailable_reason": "plain-out-param-inferred",
                    }
                )
        assign = re.search(
            r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*" + re.escape(callee) + r"\s*\(", line
        )
        if assign and _is_size_like_name(assign.group("lhs")):
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "source_ea": _site_ea_for_line(function_ea, line_no),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "source_kind": "return-value",
                    "size_expr": assign.group("lhs"),
                    "width_bits": width_bits,
                    "signedness": "unknown",
                    "trust_boundary": "unknown",
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                        "callee": callee,
                    },
                    "confidence": 0.45,
                    "partial": True,
                    "unavailable_reason": "return-value-type-unknown",
                }
            )
    return facts


def _extract_size_sources_from_code(
    function_ea: int, function_name: str, code: str
) -> list[dict[str, Any]]:
    facts = _extract_function_arg_size_sources(function_ea, function_name, code)
    seen_exprs = {fact["size_expr"] for fact in facts}
    for line_no, line in enumerate(code.splitlines(), start=1):
        for fact in _size_source_from_reader_call(function_ea, line_no, line):
            key = fact["size_expr"]
            if key not in seen_exprs:
                facts.append(fact)
                seen_exprs.add(key)
        ptr_load = re.search(
            r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]*\)\s*)?\*\s*(?:\+\+|--)?\s*(?P<ptr>[A-Za-z_]\w*)",
            line,
        )
        if ptr_load:
            lhs = ptr_load.group("lhs")
            ptr = ptr_load.group("ptr")
            if lhs not in seen_exprs and ptr.lower() not in {"this", "nullptr", "null"}:
                facts.append(
                    {
                        "function_ea": hex(function_ea),
                        "source_ea": _site_ea_for_line(function_ea, line_no),
                        "site_ea": _site_ea_for_line(function_ea, line_no),
                        "source_kind": "input-buffer",
                        "size_expr": lhs,
                        "width_bits": 8,
                        "signedness": "unsigned",
                        "trust_boundary": "unknown",
                        "line_no": line_no,
                        "line_text": line.strip(),
                        "source_refs": {
                            "source": "decompile",
                            "function_ea": hex(function_ea),
                            "line_no": line_no,
                            "pointer_expr": ptr,
                        },
                        "confidence": 0.35,
                        "partial": True,
                        "unavailable_reason": "pointer-load-trust-boundary-unknown",
                    }
                )
                seen_exprs.add(lhs)
        for match in re.finditer(
            r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<base>[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*(?:len|length|size|count|capacity|cap)[A-Za-z_]\w*)",
            line,
            re.IGNORECASE,
        ):
            lhs = match.group("lhs")
            if lhs in seen_exprs:
                continue
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "source_ea": _site_ea_for_line(function_ea, line_no),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "source_kind": "field-load",
                    "size_expr": lhs,
                    "width_bits": None,
                    "signedness": "unknown",
                    "trust_boundary": "unknown",
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.5,
                    "partial": True,
                    "unavailable_reason": "field-type-unknown",
                }
            )
            seen_exprs.add(lhs)
    return facts


def _extract_identifier_tokens(expr: str) -> list[str]:
    keywords = {
        "if",
        "return",
        "sizeof",
        "static_cast",
        "reinterpret_cast",
        "const_cast",
        "operator",
        "new",
        "delete",
        "unsigned",
        "signed",
        "int",
        "char",
        "long",
        "short",
        "size_t",
        "uint64_t",
        "uint32_t",
        "uint16_t",
        "uint8_t",
    }
    return [
        item for item in re.findall(r"\b[A-Za-z_]\w*\b", expr) if item not in keywords
    ]


def _transform_kind_for_rhs(rhs: str, lhs: str) -> tuple[str, str]:
    text = rhs.strip()
    # Outer cast detection: C++ static_cast or C-style cast.
    # Uses [^)]* (not [^)]+) to allow IDA types that start with _ (e.g. _DWORD).
    # Uses [\w(] instead of \w+ to handle cast-of-expression: (type)(a + b).
    _CAST_OUTER = (
        r"\([^)]*(?:int|size_t|char|long|short|_BYTE|_WORD|_DWORD)[^)]*\)\s*[\w(]"
    )
    if re.search(r"static_cast\s*<\s*[^>]+>\s*\(", text) or re.search(
        _CAST_OUTER, text
    ):
        conversion_kind = (
            "signed-to-unsigned"
            if re.search(r"unsigned|size_t|uint", text, re.IGNORECASE)
            else "unknown"
        )
        # Narrow (≤ 32-bit) cast → truncate.  Includes IDA decompiler type names.
        _TRUNCATE_TYPES = (
            r"unsigned\s+int|unsigned\s+__int(?:8|16|32)"
            r"|uint(?:8|16|32)_t"
            r"|_(?:BYTE|WORD|DWORD)"
            r"|__int(?:8|16|32)"
            r"|int|short|char"
        )
        if re.search(r"\(\s*(?:" + _TRUNCATE_TYPES + r")\s*\)", text, re.IGNORECASE):
            return "truncate", conversion_kind
        return "cast", conversion_kind
    if "<<" in text or ">>" in text:
        return "shift", "none"
    if "*" in text:
        return "mul", "none"
    if re.search(r"\b(?:min|std::min)\s*\(", text):
        return "min", "none"
    if re.search(r"\b(?:max|std::max)\s*\(", text):
        return "max", "none"
    if "%" in text and ("+" in text or "+=" in lhs):
        return "align", "none"
    if "+" in text:
        return "add", "none"
    if "-" in text:
        return "subtract", "none"
    return "unknown", "unknown"


def _extract_truncation_from_alloc_args(
    function_ea: int, line_no: int, line: str
) -> list[dict[str, Any]]:
    """Emit a truncate fact when a narrowing C-style cast appears inside an allocator argument.

    IDA's decompiler frequently inlines the truncation inside the alloc call, e.g.:
        dst = malloc((unsigned int)(payload_length + 8));
    The outer loop skips such lines entirely, so we handle them here before the continue.
    """
    _TRUNCATE_TYPES = (
        r"unsigned\s+int|unsigned\s+__int(?:8|16|32)"
        r"|uint(?:8|16|32)_t"
        r"|_(?:BYTE|WORD|DWORD)"
        r"|__int(?:8|16|32)"
        r"|int|short|char"
    )
    _TRUNCATE_PAT = re.compile(r"\(\s*(?:" + _TRUNCATE_TYPES + r")\s*\)", re.IGNORECASE)
    _CAST_OUTER = (
        r"\([^)]*(?:int|size_t|char|long|short|_BYTE|_WORD|_DWORD)[^)]*\)\s*[\w(]"
    )
    facts: list[dict[str, Any]] = []
    # Walk over each occurrence of (type)... inside the line
    for cast_m in _TRUNCATE_PAT.finditer(line):
        # Verify the outer cast detection fires for this cast site
        remainder = line[cast_m.start() :]
        if not (
            re.search(r"static_cast\s*<\s*[^>]+>\s*\(", remainder)
            or re.search(_CAST_OUTER, remainder)
        ):
            continue
        cast_text = remainder
        conversion_kind = (
            "signed-to-unsigned"
            if re.search(r"unsigned|size_t|uint", cast_m.group(0), re.IGNORECASE)
            else "unknown"
        )
        facts.append(
            {
                "function_ea": hex(function_ea),
                "site_ea": _site_ea_for_line(function_ea, line_no),
                "op_kind": "truncate",
                "input_exprs": _extract_identifier_tokens(cast_text),
                "output_expr": "",
                "input_width_bits": None,
                "output_width_bits": None,
                "input_signedness": "unknown",
                "output_signedness": "unsigned",
                "conversion_kind": conversion_kind,
                "line_no": line_no,
                "line_text": line.strip(),
                "source_refs": {
                    "source": "decompile",
                    "function_ea": hex(function_ea),
                    "line_no": line_no,
                },
                "confidence": 0.55,
                "partial": True,
                "unavailable_reason": "width-or-signedness-unknown",
            }
        )
        break  # one truncate fact per alloc call is sufficient
    return facts


def _extract_size_transforms_from_code(
    function_ea: int, code: str
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        if re.search(
            r"\b(?:malloc|calloc|realloc|operator\s+new|new\s+[A-Za-z_:]|\bfree)\b",
            line,
        ):
            # Truncation casts embedded in allocator arguments must be extracted before skipping.
            # e.g. malloc((unsigned int)(payload_length + 8))
            if re.search(r"\b(?:malloc|calloc|operator\s+new)\b", line):
                facts.extend(
                    _extract_truncation_from_alloc_args(function_ea, line_no, line)
                )
            # Realloc lines: extract the realloc-shrink fact, then skip.
            if re.search(r"\brealloc\s*\(", line):
                m = re.search(
                    r"(?P<lhs>[A-Za-z_]\w*)\s*(?P<op>\+=|-=|\*=|=)\s*(?P<rhs>[^;]+);",
                    line,
                )
                if m:
                    rhs = m.group("rhs").strip()
                    if re.search(r"\brealloc\s*\(", rhs):
                        args_match = re.search(r"\brealloc\s*\((?P<args>[^)]*)\)", rhs)
                        args = (
                            _split_arguments(args_match.group("args"))
                            if args_match
                            else []
                        )
                        facts.append(
                            {
                                "function_ea": hex(function_ea),
                                "site_ea": _site_ea_for_line(function_ea, line_no),
                                "op_kind": "realloc-shrink",
                                "input_exprs": [
                                    arg.strip() for arg in args if arg.strip()
                                ],
                                "output_expr": m.group("lhs"),
                                "input_width_bits": None,
                                "output_width_bits": None,
                                "input_signedness": "unknown",
                                "output_signedness": "unknown",
                                "conversion_kind": "none",
                                "line_no": line_no,
                                "line_text": line.strip(),
                                "source_refs": {
                                    "source": "decompile",
                                    "function_ea": hex(function_ea),
                                    "line_no": line_no,
                                },
                                "confidence": 0.6,
                                "partial": True,
                                "unavailable_reason": "realloc-capacity-relation-not-proven",
                            }
                        )
            continue
        match = re.search(
            r"(?P<lhs>[A-Za-z_]\w*)\s*(?P<op>\+=|-=|\*=|=)\s*(?P<rhs>[^;]+);", line
        )
        if not match:
            continue
        lhs = match.group("lhs")
        rhs = match.group("rhs").strip()
        op_kind, conversion_kind = _transform_kind_for_rhs(
            rhs, lhs if match.group("op") != "=" else ""
        )
        if match.group("op") == "+=" and "%" in rhs:
            op_kind, conversion_kind = "align", "none"
        if op_kind == "unknown" and not _is_size_like_name(lhs):
            continue
        inputs = _extract_identifier_tokens(rhs)
        if match.group("op") != "=":
            inputs = sorted(set([lhs, *inputs]))
        facts.append(
            {
                "function_ea": hex(function_ea),
                "site_ea": _site_ea_for_line(function_ea, line_no),
                "op_kind": op_kind,
                "input_exprs": inputs,
                "output_expr": lhs,
                "input_width_bits": None,
                "output_width_bits": None,
                "input_signedness": "unknown",
                "output_signedness": "unknown",
                "conversion_kind": conversion_kind,
                "line_no": line_no,
                "line_text": line.strip(),
                "source_refs": {
                    "source": "decompile",
                    "function_ea": hex(function_ea),
                    "line_no": line_no,
                },
                "confidence": 0.55,
                "partial": True,
                "unavailable_reason": "width-or-signedness-unknown",
            }
        )
    return facts


def _guard_kind_for_condition(condition: str) -> str:
    text = condition.lower()
    if re.search(r"\+\s*\w+\s*<\s*\w+|\w+\s*<\s*\w+\s*\+", text):
        return "overflow"
    if re.search(
        r"\b(?:total|sum|aligned)[a-z0-9_]*\s*<\s*[a-z_]*(?:len|size|count|capacity|alloc)[a-z0-9_]*",
        text,
    ):
        return "overflow"
    if "remaining" in text:
        return "remaining"
    if "capacity" in text or ".size" in text or "->size" in text:
        return "capacity"
    if "null" in text or "nullptr" in text or "!" in text:
        return "null"
    if re.search(r"[<>]=?", text):
        return "range"
    return "unknown"


def _extract_size_guards_from_code(function_ea: int, code: str) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    lines = code.splitlines()
    for line_no, line in enumerate(lines, start=1):
        match = re.search(r"\bif\s*\((?P<cond>.*)\)", line)
        if not match:
            continue
        condition = match.group("cond").strip()
        guarded = [
            token
            for token in _extract_identifier_tokens(condition)
            if _is_size_like_name(token) or token.lower() in {"remaining", "capacity"}
        ]
        guard_kind = _guard_kind_for_condition(condition)
        if guard_kind == "unknown" and not guarded:
            continue
        scope = "unknown"
        dominance = "unknown"
        if re.search(r"\breturn\b|\bgoto\b|\bthrow\b", line):
            scope = "early-exit-same-line"
            dominance = "partial"
        elif line_no < len(lines):
            next_line = lines[line_no].strip()
            if re.search(r"\breturn\b|\bgoto\b|\bthrow\b", next_line):
                scope = "early-exit-next-line"
                dominance = "partial"
            elif "=" in next_line and any(token in next_line for token in guarded):
                scope = "local-clamp-or-update"
                dominance = "partial"
        facts.append(
            {
                "function_ea": hex(function_ea),
                "site_ea": _site_ea_for_line(function_ea, line_no),
                "guard_kind": (
                    "clamp"
                    if scope == "local-clamp-or-update" and guard_kind == "range"
                    else guard_kind
                ),
                "guard_expr": condition,
                "guarded_exprs": guarded,
                "dominates_site_eas": [],
                "dominance": dominance,
                "guard_scope": scope,
                "line_no": line_no,
                "line_text": line.strip(),
                "source_refs": {
                    "source": "decompile",
                    "function_ea": hex(function_ea),
                    "line_no": line_no,
                },
                "confidence": 0.55,
                "partial": True,
                "unavailable_reason": "dominance-not-proven",
            }
        )
    return facts


def _allocation_kind_for_callee(callee: str) -> str:
    text = callee.lower()
    if text in {"malloc", "::malloc", "std::malloc", "operator new"}:
        return "libc"
    if "calloc" in text:
        return "calloc"
    if "realloc" in text:
        return "realloc"
    if text.endswith("malloc") or "alloc" in text:
        return "custom"
    if "resize" in text:
        return "vector-resize"
    if "pool" in text:
        return "pool"
    if "slab" in text:
        return "slab"
    if "create" in text:
        return "custom"
    return "unknown"


def _extract_allocation_sinks_from_code(
    function_ea: int, code: str
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        operator_new = re.search(
            r"(?:(?P<lhs>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_]\w*)\s*=\s*)?"
            r"operator\s+new(?:\[\])?\s*\((?P<size>[^;)]*)\)",
            line,
        )
        if operator_new:
            size_expr = operator_new.group("size").strip()
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "sink_kind": "new",
                    "size_expr": size_expr,
                    "returned_ptr_expr": (operator_new.group("lhs") or "").strip(),
                    "capacity_expr": size_expr,
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                        "callee": "operator new",
                    },
                    "confidence": 0.6,
                    "partial": True,
                    "unavailable_reason": "alias-status-not-proven",
                }
            )
        assign_prefix = r"(?:(?P<lhs>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_]\w*)\s*=\s*)?"
        for match in re.finditer(
            assign_prefix
            + r"(?P<callee>[A-Za-z_:]\w*(?:::\w+)*)\s*\((?P<args>[^;]*)\)",
            line,
        ):
            callee = match.group("callee")
            sink_kind = _allocation_kind_for_callee(callee)
            args = _split_arguments(match.group("args"))
            if not args:
                continue
            inferred_custom = False
            if sink_kind == "unknown":
                lhs = (match.group("lhs") or "").strip()
                size_like_args = [
                    arg
                    for arg in args
                    if _is_size_like_name(arg)
                    or re.search(r"len|size|count|capacity|bytes|bound", arg, re.I)
                ]
                if (
                    lhs
                    and size_like_args
                    and not _callee_likely_nonallocator(callee)
                    and (_is_pointer_like_name(lhs) or len(args) >= 2)
                ):
                    sink_kind = "custom"
                    inferred_custom = True
                else:
                    continue
            size_expr = args[1] if sink_kind == "realloc" and len(args) > 1 else args[0]
            if sink_kind == "custom" and len(args) > 1:
                size_expr = next(
                    (
                        arg
                        for arg in args
                        if _is_size_like_name(arg)
                        or re.search(r"len|size|count|capacity", arg, re.I)
                    ),
                    args[0],
                )
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "sink_kind": sink_kind,
                    "size_expr": size_expr.strip(),
                    "returned_ptr_expr": (match.group("lhs") or "").strip(),
                    "capacity_expr": size_expr.strip(),
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                        "callee": callee,
                    },
                    "confidence": 0.45 if inferred_custom else 0.6,
                    "partial": True,
                    "unavailable_reason": (
                        "callee-name-not-allocator-like"
                        if inferred_custom
                        else "alias-status-not-proven"
                    ),
                }
            )
        for match in re.finditer(
            r"new\s+(?:[A-Za-z_:]\w*)\s*\[\s*(?P<size>[^\]]+)\]", line
        ):
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "sink_kind": "new",
                    "size_expr": match.group("size").strip(),
                    "returned_ptr_expr": "",
                    "capacity_expr": match.group("size").strip(),
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.6,
                    "partial": True,
                    "unavailable_reason": "returned-pointer-unavailable",
                }
            )
    return facts


def _access_sink_kind_for_callee(callee: str) -> str:
    text = callee.lower().split("::")[-1]
    if text in {"memcpy", "memcpy_s"}:
        return "memcpy"
    if text == "memmove":
        return "memmove"
    if "read" in text and "buffer" in text:
        return "stream-read-into-buffer"
    if "write" in text or "decode" in text:
        return "decoder-write"
    return "unknown"


def _infer_bound_expr_near_store(
    lines: list[str], line_no: int, index_expr: str
) -> str:
    index_tokens = set(_extract_identifier_tokens(index_expr))
    if not index_tokens:
        return ""
    start = max(0, line_no - 4)
    end = min(len(lines), line_no + 4)
    for candidate in lines[start:end]:
        if not any(token in candidate for token in index_tokens):
            continue
        for match in re.finditer(
            r"(?P<lhs>[A-Za-z_]\w*)\s*(?:>=|>|<=|<|==|!=)\s*(?P<rhs>[A-Za-z_]\w*)|(?P<rhs2>[A-Za-z_]\w*)\s*(?:>=|>|<=|<|==|!=)\s*(?P<lhs2>[A-Za-z_]\w*)",
            candidate,
        ):
            lhs = match.group("lhs") or match.group("lhs2") or ""
            rhs = match.group("rhs") or match.group("rhs2") or ""
            if lhs in index_tokens and rhs and rhs not in index_tokens:
                return rhs
            if rhs in index_tokens and lhs and lhs not in index_tokens:
                return lhs
    return ""


def _index_expr_from_pointer_dest(dest_expr: str) -> str:
    text = str(dest_expr or "")
    for part in reversed(re.split(r"\+", text)):
        tokens = _extract_identifier_tokens(part.replace("++", "").replace("--", ""))
        if tokens:
            return tokens[-1]
    return ""


def _is_fixed_offset_pointer_store(dest_expr: str) -> bool:
    text = str(dest_expr or "").strip()
    if not text:
        return False
    if "++" in text or "--" in text or "[" in text or "]" in text:
        return False
    if re.search(r"[+\-]\s*[A-Za-z_]\w*", text):
        return False
    if re.fullmatch(r"\(?\s*(?:this|[A-Za-z_]\w*)\s*\)?", text):
        return True
    if re.search(r"(?:->|\.)\s*[A-Za-z_]\w*", text) and not re.search(
        r"[+\-]\s*(?:0x[0-9a-fA-F]+|\d+)", text
    ):
        return True
    return bool(
        re.fullmatch(
            r"\(?\s*(?:this|[A-Za-z_]\w*)\s*\)?(?:\s*[+\-]\s*(?:0x[0-9a-fA-F]+|\d+)[uUlL]*)+",
            text,
        )
    )


def _extract_access_sinks_from_code(
    function_ea: int, code: str
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    lines = code.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for match in re.finditer(
            r"(?P<callee>[A-Za-z_:]\w*(?:::\w+)*)\s*\((?P<args>[^;]*)\)", line
        ):
            callee = match.group("callee")
            sink_kind = _access_sink_kind_for_callee(callee)
            if sink_kind == "unknown":
                continue
            args = _split_arguments(match.group("args"))
            if len(args) < 3:
                continue
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "direction": "write",
                    "sink_kind": sink_kind,
                    "source_expr": args[1].strip(),
                    "dest_expr": args[0].strip(),
                    "bound_expr": args[2].strip(),
                    "element_width": 1,
                    "allocation_ref": "",
                    "allocation_ref_status": "unknown",
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                        "callee": callee,
                    },
                    "confidence": 0.65,
                    "partial": True,
                    "unavailable_reason": "allocation-alias-unknown",
                }
            )
        store = re.search(
            r"(?P<dest>[A-Za-z_]\w*(?:->|\.)?[A-Za-z_]\w*)\s*\[\s*(?P<index>[^\]]+)\s*\]\s*(?:\+\+)?\s*=",
            line,
        )
        if store:
            index_expr = store.group("index").strip()
            bound_expr = (
                _infer_bound_expr_near_store(lines, line_no, index_expr) or index_expr
            )
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "direction": "write",
                    "sink_kind": "indexed-store",
                    "source_expr": "",
                    "dest_expr": store.group("dest").strip(),
                    "bound_expr": bound_expr,
                    "element_width": 1,
                    "allocation_ref": "",
                    "allocation_ref_status": "unknown",
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.5,
                    "partial": True,
                    "unavailable_reason": "write-bound-unknown",
                }
            )
        ptr_store = re.search(
            r"\*\s*\([^)]+\)\s*\(?\s*(?P<dest>[^=;]+?)\s*\)?\s*=\s*(?P<src>[^;]+);",
            line,
        )
        if ptr_store:
            dest_expr = ptr_store.group("dest").strip()
            if _is_fixed_offset_pointer_store(dest_expr):
                continue
            index_expr = _index_expr_from_pointer_dest(dest_expr)
            facts.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": _site_ea_for_line(function_ea, line_no),
                    "direction": "write",
                    "sink_kind": "loop-store" if "++" in dest_expr else "indexed-store",
                    "source_expr": ptr_store.group("src").strip(),
                    "dest_expr": dest_expr,
                    "bound_expr": _infer_bound_expr_near_store(
                        lines, line_no, index_expr
                    )
                    or index_expr,
                    "element_width": 1,
                    "allocation_ref": "",
                    "allocation_ref_status": "unknown",
                    "line_no": line_no,
                    "line_text": line.strip(),
                    "source_refs": {
                        "source": "decompile",
                        "function_ea": hex(function_ea),
                        "line_no": line_no,
                    },
                    "confidence": 0.5,
                    "partial": True,
                    "unavailable_reason": "allocation-alias-unknown",
                }
            )
    return facts


def _extract_custom_allocator_state_from_code(
    function_ea: int, code: str
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        lower = stripped.lower()
        is_signature_like = (
            "(" in stripped
            and ")" in stripped
            and ";" not in stripped
            and not lower.startswith(("if", "while", "for", "switch"))
        )
        if is_signature_like:
            continue
        state_kind = "unknown"
        if re.search(r"(curr|current).*(\+=|=)|(\+=|=).*(curr|current)", lower):
            state_kind = "curr-pointer"
        if re.search(r"\bif\s*\(.*(?:remaining|capacity).*[<>]=?", lower):
            state_kind = "remaining-capacity"
        if re.search(r"\+=\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*\+=", stripped) and re.search(
            r"curr|current|ptr|mem", lower
        ):
            state_kind = "bump-advance"
        if re.search(r"\bif\s*\(.*(?:remaining|capacity).*[<>]=?", lower):
            state_kind = "capacity-check"
        if re.search(r"\breset\b|\bclear\b", lower) and re.search(
            r"curr|remaining|capacity|base|end", lower
        ):
            state_kind = "reset"
        if state_kind == "unknown":
            continue
        facts.append(
            {
                "function_ea": hex(function_ea),
                "site_ea": _site_ea_for_line(function_ea, line_no),
                "state_kind": state_kind,
                "state_expr": stripped,
                "update_expr": (
                    stripped if any(op in stripped for op in ("+=", "-=", "=")) else ""
                ),
                "line_no": line_no,
                "line_text": stripped,
                "source_refs": {
                    "source": "decompile",
                    "function_ea": hex(function_ea),
                    "line_no": line_no,
                },
                "confidence": 0.5,
                "partial": True,
                "unavailable_reason": "custom-allocator-model-partial",
            }
        )
    return facts


def _extract_size_flow_facts_from_code(
    function_ea: int, function_name: str, code: str
) -> dict[str, list[dict[str, Any]]]:
    return {
        "size_sources": _extract_size_sources_from_code(
            function_ea, function_name, code
        ),
        "size_transforms": _extract_size_transforms_from_code(function_ea, code),
        "guards": _extract_size_guards_from_code(function_ea, code),
        "allocation_sinks": _extract_allocation_sinks_from_code(function_ea, code),
        "access_sinks": _extract_access_sinks_from_code(function_ea, code),
        "custom_allocator_state": _extract_custom_allocator_state_from_code(
            function_ea, code
        ),
    }


def _disasm_line_looks_like_data_directive(text: str) -> bool:
    return bool(
        re.match(r"\s*(?:DCB|DCW|DCD|DCQ|DB|DW|DD|DQ)\b", str(text or "").strip(), re.I)
    )


def _generate_disasm_line_text(ea: int) -> str:
    import ida_lines

    text = ida_lines.generate_disasm_line(ea, 0) or ""
    try:
        text = ida_lines.tag_remove(text)
    except Exception:
        text = re.sub(r"<[^>]+>", "", str(text))
    text = str(text).strip()
    if not _disasm_line_looks_like_data_directive(text):
        return text

    try:
        import idc

        create_insn = getattr(idc, "create_insn", None)
        if callable(create_insn):
            create_insn(ea)
            text = ida_lines.generate_disasm_line(ea, 0) or text
            try:
                text = ida_lines.tag_remove(text)
            except Exception:
                text = re.sub(r"<[^>]+>", "", str(text))
            text = str(text).strip()
    except Exception:
        pass
    return text


def _disasm_function_lines(
    function_ea: int, *, max_instructions: int = 500
) -> list[dict[str, Any]]:
    try:
        import ida_funcs
        import ida_ua
        import idaapi

        func = ida_funcs.get_func(function_ea)
        end_ea = getattr(func, "end_ea", None) if func else None
        ea = getattr(func, "start_ea", function_ea) if func else function_ea
        lines: list[dict[str, Any]] = []
        badaddr = getattr(idaapi, "BADADDR", -1)
        for _ in range(max_instructions):
            if end_ea is not None and ea >= end_ea:
                break
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0:
                break
            text = _generate_disasm_line_text(ea)
            lines.append({"addr": hex(ea), "text": text, "size": int(length)})
            next_ea = idaapi.next_head(ea, end_ea or ea + length)
            if next_ea == badaddr or next_ea <= ea:
                ea += length
            else:
                ea = next_ea
        return lines
    except Exception:
        return []


def _is_stack_or_frame_register(reg: str) -> bool:
    return str(reg or "").upper() in {"SP", "WSP", "X29", "W29", "FP"}


def _aarch64_reg_aliases(reg: str) -> set[str]:
    text = str(reg or "").strip().upper()
    match = re.fullmatch(r"([WX])(\d+)", text)
    if not match:
        return {text} if text else set()
    idx = match.group(2)
    return {f"W{idx}", f"X{idx}"}


def _aarch64_reg_width_bits(reg: str) -> int:
    text = str(reg or "").strip().upper()
    if text.startswith("X"):
        return 64
    if text.startswith("W"):
        return 32
    return 0


def _disasm_mem_family(base: str, rest: str) -> str:
    base_reg = str(base or "").strip().upper()
    if _is_stack_or_frame_register(base_reg):
        return ""
    text = str(rest or "")
    offset = "0"
    imm = re.search(r"#(?P<imm>-?(?:0x[0-9a-fA-F]+|\d+))", text)
    if imm:
        offset = imm.group("imm").lower()
    elif text.strip():
        regs = [item.upper() for item in re.findall(r"\b[WX]\d+\b", text)]
        if regs:
            return ""
    return f"mem:{base_reg}+{offset}"


def _reg_used_soon(
    lines: list[dict[str, Any]], line_index: int, reg: str, *, window: int = 24
) -> bool:
    aliases = _aarch64_reg_aliases(reg)
    if not aliases:
        return False
    end = min(len(lines), line_index + window + 1)
    for item in lines[line_index + 1 : end]:
        text = str(item.get("text") or "").upper()
        if any(re.search(rf"\b{re.escape(alias)}\b", text) for alias in aliases):
            return True
    return False


def _infer_disasm_store_bound(
    lines: list[dict[str, Any]],
    line_index: int,
    *,
    address_regs: list[str],
    source_reg: str,
) -> str:
    if address_regs:
        index_reg = address_regs[-1]
        loop_bound = _infer_disasm_loop_bound_for_index(lines, line_index, index_reg)
        if loop_bound:
            return loop_bound
        return index_reg
    start = max(0, line_index - 8)
    for previous in reversed(lines[start:line_index]):
        text = str(previous.get("text") or "").strip()
        match = re.search(
            r"\b(?P<op>SUBS|ADDS|CMP)\s+(?P<lhs>[WX]\d+),\s*(?P<rhs>[WX]\d+|#[^\s,]+)",
            text,
            re.I,
        )
        if not match:
            continue
        lhs = match.group("lhs").upper()
        rhs = match.group("rhs").upper()
        if lhs != source_reg:
            return lhs
        if rhs.startswith(("W", "X")) and rhs != source_reg:
            return rhs
    return ""


def _infer_disasm_loop_bound_for_index(
    lines: list[dict[str, Any]], line_index: int, index_reg: str
) -> str:
    index_aliases = _aarch64_reg_aliases(index_reg)
    if not index_aliases:
        return ""

    def scan(indices: range) -> str:
        for idx in indices:
            text = str(lines[idx].get("text") or "").strip()
            match = re.search(
                r"\bCMP\s+(?P<lhs>[WX]\d+),\s*(?P<rhs>[WX]\d+|#[^\s,]+)",
                text,
                re.I,
            )
            if not match:
                continue
            lhs = match.group("lhs").upper()
            rhs = match.group("rhs").upper()
            lhs_aliases = _aarch64_reg_aliases(lhs)
            rhs_aliases = (
                _aarch64_reg_aliases(rhs) if rhs.startswith(("W", "X")) else set()
            )
            if (
                lhs_aliases & index_aliases
                and rhs_aliases
                and not rhs_aliases <= index_aliases
            ):
                return rhs
            if (
                rhs_aliases & index_aliases
                and lhs_aliases
                and not lhs_aliases <= index_aliases
            ):
                return lhs
        return ""

    forward = scan(range(line_index + 1, min(len(lines), line_index + 9)))
    if forward:
        return forward
    return scan(range(line_index - 1, max(-1, line_index - 9), -1))


def _disasm_reg_matches(reg: str, candidates: set[str]) -> bool:
    aliases = _aarch64_reg_aliases(reg)
    return bool(aliases and any(alias in aliases for alias in candidates))


def _disasm_conditional_branch(text: str) -> str:
    match = re.search(r"\bB\.(?P<cond>[A-Z]{1,2})\b", str(text or ""), re.I)
    return match.group("cond").upper() if match else ""


def _disasm_has_conditional_branch(
    lines: list[dict[str, Any]],
    start_index: int,
    *,
    window: int = 3,
    conditions: set[str] | None = None,
) -> bool:
    end = min(len(lines), start_index + window + 1)
    for item in lines[start_index:end]:
        cond = _disasm_conditional_branch(str(item.get("text") or ""))
        if cond and (conditions is None or cond in conditions):
            return True
    return False


def _disasm_has_alignment_signal(
    lines: list[dict[str, Any]], start_index: int, end_index: int
) -> bool:
    for item in lines[max(0, start_index) : min(len(lines), end_index)]:
        text = str(item.get("text") or "").upper()
        if not re.search(r"\b(?:AND|BIC|TST|CSEL|ADD|SUB)\b", text):
            continue
        if re.search(r"#(?:0X)?7\b|#(?:0X)?8\b|0XFFFFFFFFFFFFFFF8\b", text):
            return True
    return False


def _disasm_reg_loaded_from_memory_nearby(
    lines: list[dict[str, Any]],
    reg: str,
    *,
    start_index: int,
    end_index: int,
) -> bool:
    aliases = _aarch64_reg_aliases(reg)
    for item in lines[max(0, start_index) : min(len(lines), end_index)]:
        text = str(item.get("text") or "").strip()
        load = re.search(
            r"\b(?:LDR|LDUR|LDRSW)\s+(?P<dst>[WX]\d+),\s*\[(?P<base>X\d+|SP|X29)(?P<rest>[^\]]*)\]",
            text,
            re.I,
        )
        if not load or load.group("dst").upper() not in aliases:
            continue
        if not _is_stack_or_frame_register(load.group("base")):
            return True
    return False


def _disasm_bump_remaining_capacity_check(
    lines: list[dict[str, Any]],
    line_index: int,
    allocator_add: re.Match[str],
    *,
    function_ea: int,
    addr: str,
    text: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    sum_reg = allocator_add.group("sum").upper()
    lhs_reg = allocator_add.group("lhs").upper()
    rhs_reg = allocator_add.group("rhs").upper()
    candidate_regs = set(_aarch64_reg_aliases(sum_reg))
    overflow_sensitive = str(allocator_add.group("op")).upper() == "ADDS"
    search_end = min(len(lines), line_index + 24)
    align_seen = _disasm_has_alignment_signal(lines, line_index + 1, search_end)

    for next_index in range(line_index + 1, search_end):
        next_text = str(lines[next_index].get("text") or "").strip()
        next_addr = str(lines[next_index].get("addr") or addr)

        add = re.search(
            r"\b(?P<op>ADD|ADDS)\s+(?P<dst>[WX]\d+),\s*(?P<a>[WX]\d+),\s*(?P<b>[WX]\d+)\b",
            next_text,
            re.I,
        )
        if add and (
            _disasm_reg_matches(add.group("a").upper(), candidate_regs)
            or _disasm_reg_matches(add.group("b").upper(), candidate_regs)
        ):
            candidate_regs.update(_aarch64_reg_aliases(add.group("dst").upper()))
            if add.group("op").upper() == "ADDS":
                overflow_sensitive = True
            continue

        check = re.search(
            r"\bSUBS\s+(?P<dst>[WX]\d+),\s*"
            r"(?P<capacity>[WX]\d+),\s*"
            r"(?P<size>[WX]\d+)\b",
            next_text,
            re.I,
        )
        if not check:
            check = re.search(
                r"\bCMP\s+(?P<capacity>[WX]\d+),\s*(?P<size>[WX]\d+)\b",
                next_text,
                re.I,
            )
        if not check:
            continue

        capacity_reg = check.group("capacity").upper()
        size_reg = check.group("size").upper()
        if not _disasm_reg_matches(size_reg, candidate_regs):
            continue
        if _disasm_reg_matches(capacity_reg, candidate_regs):
            continue
        has_capacity_branch = _disasm_has_conditional_branch(
            lines,
            next_index + 1,
            window=4,
            conditions={"CS", "HS", "CC", "LO", "HI", "LS", "GE", "LT"},
        )
        capacity_loaded = _disasm_reg_loaded_from_memory_nearby(
            lines,
            capacity_reg,
            start_index=line_index - 8,
            end_index=next_index + 1,
        )
        if not has_capacity_branch or not (
            capacity_loaded or align_seen or overflow_sensitive
        ):
            continue

        size_width_bits = _aarch64_reg_width_bits(size_reg)
        capacity_width_bits = _aarch64_reg_width_bits(capacity_reg)
        source_regs = [lhs_reg, rhs_reg]
        allocation = {
            "function_ea": hex(function_ea),
            "site_ea": addr,
            "sink_kind": "custom",
            "size_expr": size_reg,
            "returned_ptr_expr": "",
            "capacity_expr": capacity_reg,
            "capacity_relation": "bump-pointer-remaining-check",
            "size_width_bits": size_width_bits,
            "capacity_width_bits": capacity_width_bits,
            "overflow_sensitive": bool(
                overflow_sensitive
                or (
                    size_width_bits
                    and capacity_width_bits
                    and capacity_width_bits < size_width_bits
                )
            ),
            "line_no": 0,
            "line_text": text,
            "source_refs": {
                "source": "disasm",
                "function_ea": hex(function_ea),
                "site_ea": addr,
                "capacity_check_ea": next_addr,
            },
            "confidence": 0.42 if overflow_sensitive else 0.36,
            "partial": True,
            "unavailable_reason": "decompile-failed-disasm-bump-allocator-remaining-capacity-check",
        }
        state = {
            "function_ea": hex(function_ea),
            "site_ea": next_addr,
            "state_kind": "bump-remaining-check",
            "state_expr": f"{sum_reg}={'+'.join(source_regs)}; {next_text}",
            "update_expr": next_text,
            "allocator_state_key": capacity_reg,
            "line_no": 0,
            "line_text": next_text,
            "source_refs": {
                "source": "disasm",
                "function_ea": hex(function_ea),
                "site_ea": next_addr,
            },
            "confidence": 0.32 if capacity_loaded else 0.28,
            "partial": True,
            "unavailable_reason": "decompile-failed-disasm-custom-allocator-model-partial",
        }
        return allocation, state
    return None


def _extract_size_flow_facts_from_disasm(
    function_ea: int,
    function_name: str,
    lines: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    size_sources: list[dict[str, Any]] = []
    transforms: list[dict[str, Any]] = []
    guards: list[dict[str, Any]] = []
    allocation_sinks: list[dict[str, Any]] = []
    access_sinks: list[dict[str, Any]] = []
    custom_allocator_state: list[dict[str, Any]] = []
    seen_sources: set[str] = set()
    seen_remaining_capacity_checks: set[tuple[str, str, str]] = set()

    op_map = {
        "ADD": "add",
        "ADDS": "add",
        "SUB": "subtract",
        "SUBS": "subtract",
        "MUL": "mul",
        "MADD": "mul",
        "LSL": "shift",
        "LSR": "shift",
        "ASR": "shift",
        "UBFX": "truncate",
        "SBFIZ": "shift",
        "AND": "mask",
    }
    for line_index, line in enumerate(lines):
        addr = str(line.get("addr") or "")
        text = str(line.get("text") or "").strip()
        if not text:
            continue
        load = re.search(
            r"\b(?P<op>LDRB|LDRH|LDR|LDUR|LDRSW)\s+(?P<dst>[WX]\d+),\s*\[(?P<base>X\d+|SP|X29)(?P<rest>[^\]]*)\]",
            text,
            re.I,
        )
        if load and not _is_stack_or_frame_register(load.group("base")):
            dst = load.group("dst").upper()
            op = load.group("op").upper()
            memory_family = _disasm_mem_family(
                load.group("base"), load.group("rest") or ""
            )
            if op in {"LDR", "LDUR", "LDRSW"} and not _reg_used_soon(
                lines, line_index, dst
            ):
                memory_family = ""
            source_key = f"{dst}:{memory_family}" if memory_family else dst
            if source_key not in seen_sources and (
                op in {"LDRB", "LDRH"} or memory_family
            ):
                seen_sources.add(source_key)
                width_bits = (
                    8
                    if op == "LDRB"
                    else (
                        16
                        if op == "LDRH"
                        else 32 if dst.startswith("W") or op == "LDRSW" else 64
                    )
                )
                size_sources.append(
                    {
                        "function_ea": hex(function_ea),
                        "source_ea": addr,
                        "site_ea": addr,
                        "source_kind": "input-buffer",
                        "size_expr": dst,
                        "source_family_key": memory_family or dst,
                        "width_bits": width_bits,
                        "signedness": (
                            "signed"
                            if op == "LDRSW"
                            else "unsigned" if op in {"LDRB", "LDRH"} else "unknown"
                        ),
                        "trust_boundary": "unknown",
                        "line_no": 0,
                        "line_text": text,
                        "source_refs": {
                            "source": "disasm",
                            "function_ea": hex(function_ea),
                            "site_ea": addr,
                        },
                        "confidence": 0.3 if op in {"LDRB", "LDRH"} else 0.22,
                        "partial": True,
                        "unavailable_reason": (
                            "decompile-failed-disasm-byte-load"
                            if op in {"LDRB", "LDRH"}
                            else "decompile-failed-disasm-struct-load"
                        ),
                    }
                )

        op_match = re.search(
            r"\b(?P<op>ADD|ADDS|SUB|SUBS|MUL|MADD|LSL|LSR|ASR|UBFX|SBFIZ|AND)\s+(?P<dst>[WX]\d+),\s*(?P<rest>.+)",
            text,
            re.I,
        )
        if op_match:
            op = op_match.group("op").upper()
            dst = op_match.group("dst").upper()
            rest = op_match.group("rest")
            regs = [item.upper() for item in re.findall(r"\b[WX]\d+\b", rest)]
            if regs:
                transforms.append(
                    {
                        "function_ea": hex(function_ea),
                        "site_ea": addr,
                        "op_kind": op_map.get(op, "unknown"),
                        "input_exprs": regs,
                        "output_expr": dst,
                        "input_width_bits": 64 if dst.startswith("X") else 32,
                        "output_width_bits": 64 if dst.startswith("X") else 32,
                        "input_signedness": "unknown",
                        "output_signedness": "unknown",
                        "conversion_kind": (
                            "none" if op not in {"UBFX", "SBFIZ"} else "truncate"
                        ),
                        "line_no": 0,
                        "line_text": text,
                        "source_refs": {
                            "source": "disasm",
                            "function_ea": hex(function_ea),
                            "site_ea": addr,
                        },
                        "confidence": 0.3,
                        "partial": True,
                        "unavailable_reason": "decompile-failed-disasm-arithmetic",
                    }
                )

        guard = re.search(
            r"\b(?P<op>CMP|CMN|TST)\s+(?P<lhs>[WX]\d+),\s*(?P<rhs>.+)", text, re.I
        )
        if guard:
            lhs = guard.group("lhs").upper()
            regs = [
                lhs,
                *[
                    item.upper()
                    for item in re.findall(r"\b[WX]\d+\b", guard.group("rhs"))
                ],
            ]
            guards.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": addr,
                    "guard_kind": "range",
                    "guard_expr": text,
                    "guarded_exprs": regs,
                    "dominates_site_eas": [],
                    "dominance": "unknown",
                    "guard_scope": "disasm-branch-context-unknown",
                    "line_no": 0,
                    "line_text": text,
                    "source_refs": {
                        "source": "disasm",
                        "function_ea": hex(function_ea),
                        "site_ea": addr,
                    },
                    "confidence": 0.25,
                    "partial": True,
                    "unavailable_reason": "decompile-failed-disasm-guard",
                }
            )

        store = re.search(
            r"\b(?P<op>STRB|STRH)\s+(?P<src>W\d+),\s*\[(?P<base>X\d+|SP|X29)(?P<rest>[^\]]*)\](?P<post>\s*,\s*#?-?(?:0x[0-9a-fA-F]+|\d+))?",
            text,
            re.I,
        )
        if store and not _is_stack_or_frame_register(store.group("base")):
            rest = store.group("rest") or ""
            regs = [item.upper() for item in re.findall(r"\b[WX]\d+\b", rest)]
            post_index = str(store.group("post") or "").strip()
            bound_expr = _infer_disasm_store_bound(
                lines,
                line_index,
                address_regs=regs,
                source_reg=store.group("src").upper(),
            )
            if not regs and not post_index:
                continue
            if not bound_expr:
                continue
            access_sinks.append(
                {
                    "function_ea": hex(function_ea),
                    "site_ea": addr,
                    "direction": "write",
                    "sink_kind": (
                        "loop-store" if post_index or regs else "indexed-store"
                    ),
                    "source_expr": store.group("src").upper(),
                    "dest_expr": f"{store.group('base').upper()}{rest}{post_index}",
                    "bound_expr": bound_expr,
                    "element_width": 1 if store.group("op").upper() == "STRB" else 2,
                    "allocation_ref": "",
                    "allocation_ref_status": "unknown",
                    "line_no": 0,
                    "line_text": text,
                    "source_refs": {
                        "source": "disasm",
                        "function_ea": hex(function_ea),
                        "site_ea": addr,
                    },
                    "confidence": 0.3,
                    "partial": True,
                    "unavailable_reason": "decompile-failed-disasm-store",
                }
            )

        allocator_add = re.search(
            r"\bADD\s+(?P<sum>X\d+),\s*(?P<cursor>X\d+),\s*(?P<size>[WX]\d+)\b",
            text,
            re.I,
        )
        if allocator_add:
            sum_reg = allocator_add.group("sum").upper()
            cursor_reg = allocator_add.group("cursor").upper()
            size_reg = allocator_add.group("size").upper()
            check_reg = ""
            check_text = ""
            check_addr = addr
            for next_line in lines[line_index + 1 : min(len(lines), line_index + 6)]:
                next_text = str(next_line.get("text") or "").strip()
                next_addr = str(next_line.get("addr") or addr)
                sub = re.search(
                    r"\bSUBS?\s+(?P<dst>[WX]\d+),\s*(?P<lhs>[WX]\d+),\s*(?P<base>[WX]\d+)\b",
                    next_text,
                    re.I,
                )
                if sub and any(
                    alias == sub.group("lhs").upper()
                    for alias in _aarch64_reg_aliases(sum_reg)
                ):
                    check_reg = sub.group("dst").upper()
                    check_text = next_text
                    check_addr = next_addr
                    continue
                cmp_line = re.search(
                    r"\bCMP\s+(?P<lhs>[WX]\d+),\s*(?P<rhs>#[^,\s]+|[WX]\d+)",
                    next_text,
                    re.I,
                )
                if (
                    cmp_line
                    and check_reg
                    and cmp_line.group("lhs").upper() in _aarch64_reg_aliases(check_reg)
                ):
                    size_width_bits = _aarch64_reg_width_bits(size_reg)
                    capacity_width_bits = _aarch64_reg_width_bits(check_reg)
                    sum_width_bits = _aarch64_reg_width_bits(sum_reg)
                    overflow_sensitive = bool(
                        size_width_bits
                        and capacity_width_bits
                        and capacity_width_bits < size_width_bits
                    ) or bool(
                        sum_width_bits
                        and capacity_width_bits
                        and capacity_width_bits < sum_width_bits
                    )
                    allocation_sinks.append(
                        {
                            "function_ea": hex(function_ea),
                            "site_ea": addr,
                            "sink_kind": "custom",
                            "size_expr": size_reg,
                            "returned_ptr_expr": cursor_reg,
                            "capacity_expr": check_reg,
                            "capacity_relation": "pointer-add-capacity-check",
                            "size_width_bits": size_width_bits,
                            "capacity_width_bits": capacity_width_bits,
                            "overflow_sensitive": overflow_sensitive,
                            "line_no": 0,
                            "line_text": text,
                            "source_refs": {
                                "source": "disasm",
                                "function_ea": hex(function_ea),
                                "site_ea": addr,
                            },
                            "confidence": 0.4 if overflow_sensitive else 0.35,
                            "partial": True,
                            "unavailable_reason": "decompile-failed-disasm-custom-allocator-capacity-check",
                        }
                    )
                    custom_allocator_state.append(
                        {
                            "function_ea": hex(function_ea),
                            "site_ea": check_addr,
                            "state_kind": "capacity-check",
                            "state_expr": f"{sum_reg}={cursor_reg}+{size_reg}; {check_text}; {next_text}",
                            "update_expr": f"{cursor_reg}+={size_reg}",
                            "allocator_state_key": cursor_reg,
                            "line_no": 0,
                            "line_text": next_text,
                            "source_refs": {
                                "source": "disasm",
                                "function_ea": hex(function_ea),
                                "site_ea": check_addr,
                            },
                            "confidence": 0.3,
                            "partial": True,
                            "unavailable_reason": "decompile-failed-disasm-custom-allocator-model-partial",
                        }
                    )
                    break

        remaining_add = re.search(
            r"\b(?P<op>ADD|ADDS)\s+(?P<sum>[WX]\d+),\s*(?P<lhs>[WX]\d+),\s*(?P<rhs>[WX]\d+)\b",
            text,
            re.I,
        )
        if remaining_add:
            detected = _disasm_bump_remaining_capacity_check(
                lines,
                line_index,
                remaining_add,
                function_ea=function_ea,
                addr=addr,
                text=text,
            )
            if detected:
                allocation, state = detected
                key = (
                    str(state.get("site_ea") or ""),
                    str(allocation.get("capacity_expr") or ""),
                    str(allocation.get("size_expr") or ""),
                )
                if key not in seen_remaining_capacity_checks:
                    seen_remaining_capacity_checks.add(key)
                    allocation_sinks.append(allocation)
                    custom_allocator_state.append(state)

    return {
        "size_sources": size_sources,
        "size_transforms": transforms,
        "guards": guards,
        "allocation_sinks": allocation_sinks,
        "access_sinks": access_sinks,
        "custom_allocator_state": custom_allocator_state,
    }


def _size_flow_fact_identity(item: dict[str, Any]) -> tuple[str, str, str, str]:
    refs = item.get("source_refs") if isinstance(item.get("source_refs"), dict) else {}
    return (
        str(item.get("site_ea") or item.get("source_ea") or ""),
        str(
            item.get("sink_kind")
            or item.get("op_kind")
            or item.get("guard_kind")
            or item.get("source_kind")
            or item.get("state_kind")
            or ""
        ),
        str(
            item.get("size_expr")
            or item.get("output_expr")
            or item.get("guard_expr")
            or item.get("bound_expr")
            or item.get("state_expr")
            or ""
        ),
        str(refs.get("source") or ""),
    )


def _merge_size_flow_fact_lists(
    raw_result: dict[str, Any], overlay: dict[str, list[dict[str, Any]]]
) -> bool:
    changed = False
    for key in (
        "size_sources",
        "size_transforms",
        "guards",
        "allocation_sinks",
        "access_sinks",
        "custom_allocator_state",
    ):
        existing = raw_result.setdefault(key, [])
        seen = {
            _size_flow_fact_identity(item)
            for item in existing
            if isinstance(item, dict)
        }
        for item in overlay.get(key) or []:
            if not isinstance(item, dict):
                continue
            identity = _size_flow_fact_identity(item)
            if identity in seen:
                continue
            existing.append(item)
            seen.add(identity)
            changed = True
    return changed


def _parse_int_literal(token: str) -> int | None:
    text = token.strip()
    if not text:
        return None
    text = re.sub(r"[uUlL]+$", "", text)
    if text.startswith(("0x", "0X")):
        try:
            return int(text, 16)
        except ValueError:
            return None
    if text.endswith(("h", "H")):
        try:
            return int(text[:-1], 16)
        except ValueError:
            return None
    if re.fullmatch(r"\d+", text):
        try:
            return int(text, 10)
        except ValueError:
            return None
    return None


def _estimate_frame_size(start_ea: int) -> dict:
    """Estimate frame size from IDA frame API and/or prologue disassembly."""
    out = {
        "total_size": None,
        "local_size": None,
        "save_area_size": None,
        "source": None,
    }

    # First try direct frame APIs.
    try:
        import ida_frame
        import ida_funcs

        fn = ida_funcs.get_func(start_ea)
        if fn:
            for attr in ("get_frame_size", "calc_frame_size"):
                if hasattr(ida_frame, attr):
                    value = getattr(ida_frame, attr)(fn)
                    if isinstance(value, int) and value > 0:
                        out["total_size"] = value
                        out["source"] = f"ida_frame.{attr}"
                        return out
    except Exception:
        pass

    # Fallback: parse function prologue disassembly.
    try:
        import ida_funcs
        import ida_lines
        import ida_ua
        import idaapi

        fn = ida_funcs.get_func(start_ea)
        if not fn:
            return out

        ea = fn.start_ea
        local_alloc = 0
        save_alloc = 0
        seen_alloc = False

        for _ in range(40):
            if ea >= fn.end_ea:
                break

            insn = ida_ua.insn_t()
            insn_len = ida_ua.decode_insn(insn, ea)
            if insn_len <= 0:
                break

            text = ida_lines.tag_remove(
                ida_lines.generate_disasm_line(ea, 0) or ""
            ).strip()
            upper = text.upper()

            # AArch64 style: SUB SP, SP, #0xD70
            m_sub = re.search(
                r"\bSUB\s+SP\s*,\s*SP\s*,\s*#(?P<imm>0X[0-9A-F]+|\d+)\b", upper
            )
            if m_sub:
                imm = _parse_int_literal(m_sub.group("imm"))
                if imm and imm > 0:
                    local_alloc += imm
                    seen_alloc = True

            # x86_64 style: sub rsp, 0x120
            m_sub_rsp = re.search(
                r"\bSUB\s+RSP\s*,\s*(?P<imm>0X[0-9A-F]+|\d+)\b", upper
            )
            if m_sub_rsp:
                imm = _parse_int_literal(m_sub_rsp.group("imm"))
                if imm and imm > 0:
                    local_alloc += imm
                    seen_alloc = True

            # AArch64 save area pattern: STP ..., [SP,#var_40]!
            m_var = re.search(r"\[SP\s*,\s*#VAR_(?P<off>[0-9A-F]+)\]!", upper)
            if m_var:
                off = _parse_int_literal(f"0x{m_var.group('off')}")
                if off and off > 0:
                    save_alloc = max(save_alloc, off)
                    seen_alloc = True

            # Alternative immediate form: [SP,#-0x40]!
            m_neg = re.search(r"\[SP\s*,\s*#-(?P<off>0X[0-9A-F]+|\d+)\]!", upper)
            if m_neg:
                off = _parse_int_literal(m_neg.group("off"))
                if off and off > 0:
                    save_alloc = max(save_alloc, off)
                    seen_alloc = True

            # Stop once we leave prologue region.
            if seen_alloc and (
                re.search(r"\bBL\b|\bCALL\b|\bRET\b|\bB\.", upper) is not None
                or re.search(r"\bCBZ\b|\bCBNZ\b", upper) is not None
            ):
                break

            next_ea = idaapi.next_head(ea, fn.end_ea)
            if next_ea == idaapi.BADADDR:
                break
            ea = next_ea

        total = local_alloc + save_alloc
        if total > 0:
            out["total_size"] = total
            out["local_size"] = local_alloc if local_alloc > 0 else None
            out["save_area_size"] = save_alloc if save_alloc > 0 else None
            out["source"] = "prologue_disasm"
    except Exception:
        pass

    return out


def _extract_stack_regions_from_code(code: str, frame_size: int | None) -> list[dict]:
    """Extract anonymous STACK[...] regions from decompiled pseudocode."""
    regions: dict[int, dict[str, Any]] = {}
    lines = code.splitlines()

    def _ensure_region(stack_index: int) -> dict[str, Any]:
        if stack_index not in regions:
            regions[stack_index] = {
                "stack_index": stack_index,
                "size": None,
                "evidence": [],
            }
        return regions[stack_index]

    for line_no, line in enumerate(lines, start=1):
        for raw_idx in re.findall(r"STACK\[(0x[0-9A-Fa-f]+|\d+)\]", line):
            idx = _parse_int_literal(raw_idx)
            if idx is None:
                continue
            region = _ensure_region(idx)
            region["evidence"].append({"line_no": line_no, "line": line.strip()})

        memset_match = re.search(
            r"memset\s*\(\s*&?STACK\[(?P<idx>0x[0-9A-Fa-f]+|\d+)\]\s*,\s*[^,]+,\s*(?P<size>0x[0-9A-Fa-f]+|\d+)[uUlL]*\s*\)",
            line,
        )
        if memset_match:
            idx = _parse_int_literal(memset_match.group("idx"))
            size = _parse_int_literal(memset_match.group("size"))
            if idx is not None:
                region = _ensure_region(idx)
                if isinstance(size, int) and size > 0:
                    region["size"] = max(region["size"] or 0, size)

        memcpy_match = re.search(
            r"memcpy(?:_s)?\s*\(\s*&?STACK\[(?P<idx>0x[0-9A-Fa-f]+|\d+)\]\s*,\s*(?P<size>0x[0-9A-Fa-f]+|\d+)",
            line,
        )
        if memcpy_match:
            idx = _parse_int_literal(memcpy_match.group("idx"))
            size = _parse_int_literal(memcpy_match.group("size"))
            if idx is not None:
                region = _ensure_region(idx)
                if isinstance(size, int) and size > 0:
                    region["size"] = max(region["size"] or 0, size)

    vars_out: list[dict] = []
    for stack_index in sorted(regions):
        region = regions[stack_index]
        offset = (
            stack_index - frame_size
            if isinstance(frame_size, int) and frame_size > 0
            else None
        )
        size = region["size"]
        type_str = (
            f"uint8_t[{size}]" if isinstance(size, int) and size > 0 else "uint8_t[]"
        )
        vars_out.append(
            {
                "offset": offset,
                "offset_expr": (
                    _format_stack_offset(offset) if offset is not None else None
                ),
                "name": f"stack_{stack_index:X}",
                "type": type_str,
                "size": size,
                "stack_index": stack_index,
                "source": "stack_region",
                "evidence": region["evidence"][:3],
            }
        )
    return vars_out


def _merge_stack_vars(primary: list[dict], extras: list[dict]) -> list[dict]:
    merged = list(primary)
    existing_offsets = {
        item.get("offset") for item in primary if isinstance(item.get("offset"), int)
    }

    for item in extras:
        off = item.get("offset")
        if isinstance(off, int) and off in existing_offsets:
            # Keep explicit lvars/comments when offset conflicts.
            continue
        merged.append(item)

    merged.sort(
        key=lambda x: (
            x.get("offset") is None,
            x.get("offset") if isinstance(x.get("offset"), int) else 0,
        )
    )
    return merged


@register_tool
def decompile(
    addr: Annotated[str, "函数地址或名称"] = "",
    addrs: Annotated[str | list[str], "函数地址列表（逗号分隔、列表或单个地址）"] = "",
) -> dict | list:
    """Decompile one or more functions to pseudocode"""
    batch_mode = bool(addrs)
    targets = normalize_list_input(addrs) if batch_mode else normalize_list_input(addr)

    if not targets:
        return {
            "addr": addr or None,
            "code": None,
            "error": "Either 'addr' or 'addrs' is required",
        }

    def _decompile_one(target: str) -> dict:
        try:
            import ida_hexrays

            start = parse_address(target)
            cfunc = ida_hexrays.decompile(start)
            if not cfunc:
                return {"addr": target, "code": None, "error": "Decompilation failed"}
            return {"addr": target, "code": str(cfunc), "error": None}
        except Exception as e:
            return {"addr": target, "code": None, "error": str(e)}

    results = [_decompile_one(target) for target in targets]
    if batch_mode:
        return results
    return results[0]


@register_tool
def get_function_prototype(
    addr: Annotated[str, "函数地址或名称"],
) -> dict:
    """Type-info-based prototype retrieval (best-effort; may be missing/inaccurate when type info is absent/inferred)"""
    try:
        import ida_typeinf
        import idaapi
        import idc

        start_ea, func_name = _resolve_function(addr)

        prototype = None
        return_type = None
        params: list[dict[str, Any]] = []

        tif = ida_typeinf.tinfo_t()
        has_tinfo = False
        try:
            if hasattr(idaapi, "get_tinfo"):
                has_tinfo = bool(idaapi.get_tinfo(tif, start_ea))
        except Exception:
            has_tinfo = False

        if not has_tinfo:
            try:
                import ida_nalt

                has_tinfo = bool(ida_nalt.get_tinfo(tif, start_ea))
            except Exception:
                has_tinfo = False

        if has_tinfo:
            try:
                prototype = tif._print(func_name)
            except Exception:
                prototype = None

            try:
                ftd = ida_typeinf.func_type_data_t()
                if tif.get_func_details(ftd):
                    if hasattr(ftd, "rettype") and hasattr(ftd.rettype, "_print"):
                        return_type = ftd.rettype._print()
                    for i, arg in enumerate(ftd):
                        arg_name = getattr(arg, "name", "") or f"arg{i}"
                        arg_type = getattr(arg, "type", None)
                        if arg_type is not None and hasattr(arg_type, "_print"):
                            arg_type_str = arg_type._print()
                        else:
                            arg_type_str = "unknown"
                        params.append(
                            {
                                "index": i,
                                "name": arg_name,
                                "type": arg_type_str,
                            }
                        )
            except Exception:
                pass

        if not prototype:
            try:
                prototype = idc.get_type(start_ea)
            except Exception:
                prototype = None

        if not prototype:
            return {
                "addr": addr,
                "resolved_addr": hex(start_ea),
                "name": func_name,
                "prototype": None,
                "return_type": None,
                "params": [],
                "error": "No type information available for function",
            }

        prototype = _normalize_prototype_text(prototype, func_name)
        parsed_ret_type, parsed_params = _parse_prototype_text(prototype)
        if return_type is None:
            return_type = parsed_ret_type
        if not params:
            params = parsed_params

        return {
            "addr": addr,
            "resolved_addr": hex(start_ea),
            "name": func_name,
            "prototype": prototype,
            "return_type": return_type,
            "params": params,
            "error": None,
        }
    except Exception as e:
        return {
            "addr": addr,
            "resolved_addr": None,
            "name": None,
            "prototype": None,
            "return_type": None,
            "params": [],
            "error": str(e),
        }


@register_tool
def get_stack_frame(
    addr: Annotated[str, "函数地址或名称"],
) -> dict:
    """Heuristic stack-frame recovery (may be incomplete; merges named locals with inferred STACK regions)"""
    try:
        import ida_hexrays

        start_ea, func_name = _resolve_function(addr)
        cfunc = ida_hexrays.decompile(start_ea)
        if not cfunc:
            return {
                "addr": addr,
                "resolved_addr": hex(start_ea),
                "function": func_name,
                "vars": [],
                "layout": [],
                "count": 0,
                "error": "Decompilation failed",
            }

        code = str(cfunc)
        vars_info = _extract_stack_vars_from_lvars(cfunc)
        if not vars_info:
            vars_info = _extract_stack_vars_from_code(code)

        frame_info = _estimate_frame_size(start_ea)
        frame_size = frame_info.get("total_size")
        stack_regions = _extract_stack_regions_from_code(
            code, frame_size if isinstance(frame_size, int) else None
        )
        vars_info = _merge_stack_vars(vars_info, stack_regions)

        layout = []
        for item in vars_info:
            size_text = (
                f"{item['size']} bytes"
                if isinstance(item["size"], int)
                else "unknown size"
            )
            if item.get("offset_expr"):
                offset_text = item["offset_expr"]
            elif item.get("stack_index") is not None:
                offset_text = f"[STACK+{item['stack_index']:X}h]"
            else:
                offset_text = "[unknown]"
            layout.append(f"{offset_text} {item['name']} {item['type']} {size_text}")

        return {
            "addr": addr,
            "resolved_addr": hex(start_ea),
            "function": func_name,
            "frame": frame_info,
            "vars": vars_info,
            "layout": layout,
            "count": len(vars_info),
            "error": None,
        }
    except Exception as e:
        return {
            "addr": addr,
            "resolved_addr": None,
            "function": None,
            "frame": {
                "total_size": None,
                "local_size": None,
                "save_area_size": None,
                "source": None,
            },
            "vars": [],
            "layout": [],
            "count": 0,
            "error": str(e),
        }


@register_tool
def search_decompiled_code(
    pattern: Annotated[
        str, "正则模式（在伪代码中搜索）；这是启发式文本搜索，不是语义证明"
    ],
    scope: Annotated[
        str,
        "搜索范围：selected_functions 优先；all_functions 会按 max_functions 限额扫描",
    ] = "all_functions",
    addrs: Annotated[
        str | list[str],
        "函数地址列表（scope=selected_functions 时使用）；优先传入 work-unit/xref/callee 函数地址",
    ] = "",
    function_filter: Annotated[
        str,
        "Glob 模式过滤函数名（仅 all_functions 生效）；大型/stripped 二进制应设置窄过滤",
    ] = "",
    max_functions: Annotated[
        int, "最多扫描函数数限额；0 被禁用，默认/全局上限为 50 以避免全库反编译卡死"
    ] = 50,
    max_matches: Annotated[int, "最多返回匹配数"] = 200,
    case_sensitive: Annotated[bool, "是否区分大小写"] = False,
) -> dict:
    """Regex search over pseudocode text.

    This is a non-semantic helper for bounded follow-up.  Prefer
    ``scope='selected_functions'`` with concrete EAs from structured facts.
    ``scope='all_functions'`` is intentionally capped by default because large
    stripped/C++ binaries can spend minutes in decompilation when no match is
    found.  ``max_functions=0`` is rejected by policy; use a controlled
    offline job for full-binary scans.
    """
    try:
        import fnmatch

        import ida_funcs
        import ida_hexrays
        import idautils

        if max_matches <= 0:
            max_matches = 200

        effective_max_functions, search_policy = _resolve_decompiled_search_limit(
            max_functions
        )
        if effective_max_functions <= 0:
            return {
                "pattern": pattern,
                "scope": scope,
                "matches": [],
                "count": 0,
                "scanned_functions": 0,
                "decompiled_functions": 0,
                "skipped": [],
                "truncated": False,
                "search_policy": search_policy,
                "error": (
                    search_policy["message"]
                    if search_policy
                    else "decompiled-code search blocked"
                ),
            }

        flags = re.MULTILINE
        if not case_sensitive:
            flags |= re.IGNORECASE
        regex = re.compile(pattern, flags)

        targets: list[int] = []
        if scope == "all_functions":
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea)
                if function_filter and not fnmatch.fnmatch(name, function_filter):
                    continue
                targets.append(ea)
        elif scope == "selected_functions":
            for target in normalize_list_input(addrs):
                try:
                    ea, _ = _resolve_function(str(target))
                    targets.append(ea)
                except Exception:
                    continue
        else:
            return {
                "pattern": pattern,
                "scope": scope,
                "matches": [],
                "count": 0,
                "error": "Invalid scope, expected 'all_functions' or 'selected_functions'",
            }

        targets = targets[:effective_max_functions]

        matches = []
        scanned = 0
        decompiled = 0
        truncated = False
        skipped: list[dict[str, str]] = []

        for fn_start in targets:
            scanned += 1
            fn_name = ida_funcs.get_func_name(fn_start)
            try:
                cfunc = ida_hexrays.decompile(fn_start)
            except Exception as e:
                skipped.append(
                    {
                        "addr": hex(fn_start),
                        "name": fn_name,
                        "error": str(e),
                    }
                )
                continue

            if not cfunc:
                skipped.append(
                    {
                        "addr": hex(fn_start),
                        "name": fn_name,
                        "error": "Decompilation failed",
                    }
                )
                continue

            decompiled += 1
            code = str(cfunc)
            for m in regex.finditer(code):
                line_no, line_text, snippet = _line_and_context(code, m.start())
                matches.append(
                    {
                        "addr": hex(fn_start),
                        "function": fn_name,
                        "line": line_no,
                        "match": m.group(0),
                        "line_text": line_text,
                        "snippet": snippet,
                    }
                )
                if len(matches) >= max_matches:
                    truncated = True
                    break
            if truncated:
                break

        return {
            "pattern": pattern,
            "scope": scope,
            "matches": matches,
            "count": len(matches),
            "scanned_functions": scanned,
            "decompiled_functions": decompiled,
            "skipped": skipped,
            "truncated": truncated,
            "search_policy": search_policy,
            "error": None,
        }
    except re.error as e:
        return {
            "pattern": pattern,
            "scope": scope,
            "matches": [],
            "count": 0,
            "error": f"Invalid regex: {e}",
        }
    except Exception as e:
        return {
            "pattern": pattern,
            "scope": scope,
            "matches": [],
            "count": 0,
            "error": str(e),
        }


@register_tool
def batch_search_decompiled_patterns(
    patterns: Annotated[
        list[dict[str, Any]], "Regex pattern specs: [{'id': str, 'regex': str}]"
    ],
    scope: Annotated[
        str, "搜索范围：all_functions 或 selected_functions"
    ] = "all_functions",
    addrs: Annotated[
        str | list[str], "函数地址列表（scope=selected_functions 时使用）"
    ] = "",
    function_filter: Annotated[
        str, "Glob 模式过滤函数名（仅 all_functions 生效）"
    ] = "",
    max_functions: Annotated[int, "最多扫描函数数；0 被禁用，默认/全局上限为 50"] = 50,
    max_matches: Annotated[int, "最多返回匹配数"] = 1000,
    case_sensitive: Annotated[bool, "是否区分大小写"] = False,
) -> dict:
    """Batch regex search over pseudocode with structured fact output."""
    compiled_patterns, diagnostics = _prepare_decompiled_pattern_specs(
        patterns,
        case_sensitive=case_sensitive,
    )
    if max_matches <= 0:
        max_matches = 1000
    effective_max_functions, search_policy = _resolve_decompiled_search_limit(
        max_functions
    )

    raw_result: dict[str, Any] = {
        "tool": "batch_search_decompiled_patterns",
        "matches": [],
        "scanned_functions": 0,
        "decompiled_functions": 0,
        "skipped": [],
        "truncated": False,
        "diagnostics": diagnostics,
        "search_policy": search_policy,
        "partial": bool(diagnostics),
    }

    if effective_max_functions <= 0:
        raw_result["diagnostics"].append(
            {
                "code": str(
                    (search_policy or {}).get("code") or "decompiled-search-blocked"
                ),
                "message": str(
                    (search_policy or {}).get("message")
                    or "decompiled-code search blocked"
                ),
            }
        )
        raw_result["partial"] = True
        return normalize_batch_search_decompiled_patterns_result(raw_result)

    if not compiled_patterns:
        return normalize_batch_search_decompiled_patterns_result(raw_result)

    try:
        import fnmatch

        import ida_funcs
        import ida_hexrays
        import idautils

        targets: list[int] = []
        if scope == "all_functions":
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea)
                if function_filter and not fnmatch.fnmatch(name, function_filter):
                    continue
                targets.append(ea)
        elif scope == "selected_functions":
            for target in normalize_list_input(addrs):
                try:
                    ea, _ = _resolve_function(str(target))
                    targets.append(ea)
                except Exception as exc:
                    raw_result["skipped"].append(
                        {
                            "addr": str(target),
                            "name": "",
                            "error": str(exc),
                        }
                    )
        else:
            raw_result["diagnostics"].append(
                {
                    "code": "invalid-scope",
                    "message": "Invalid scope, expected 'all_functions' or 'selected_functions'",
                }
            )
            raw_result["partial"] = True
            return normalize_batch_search_decompiled_patterns_result(raw_result)

        targets = targets[:effective_max_functions]

        for fn_start in targets:
            raw_result["scanned_functions"] += 1
            fn_name = ida_funcs.get_func_name(fn_start)
            try:
                cfunc = ida_hexrays.decompile(fn_start)
            except Exception as exc:
                raw_result["skipped"].append(
                    {
                        "addr": hex(fn_start),
                        "name": fn_name,
                        "error": str(exc),
                    }
                )
                raw_result["partial"] = True
                continue

            if not cfunc:
                raw_result["skipped"].append(
                    {
                        "addr": hex(fn_start),
                        "name": fn_name,
                        "error": "Decompilation failed",
                    }
                )
                raw_result["partial"] = True
                continue

            raw_result["decompiled_functions"] += 1
            code = str(cfunc)
            for spec in compiled_patterns:
                for match in spec["compiled"].finditer(code):
                    line_no, line_text, snippet = _line_and_context(code, match.start())
                    raw_result["matches"].append(
                        {
                            "pattern_id": spec["id"],
                            "function_ea": hex(fn_start),
                            "function_name": fn_name,
                            "line_no": line_no,
                            "match_text": match.group(0),
                            "line_text": line_text,
                            "snippet": snippet,
                            "raw_name": fn_name,
                            "source_refs": {
                                "source": "decompile",
                                "function_ea": hex(fn_start),
                            },
                            "confidence": 1.0,
                        }
                    )
                    if len(raw_result["matches"]) >= max_matches:
                        raw_result["truncated"] = True
                        return normalize_batch_search_decompiled_patterns_result(
                            raw_result
                        )

        return normalize_batch_search_decompiled_patterns_result(raw_result)
    except Exception as exc:
        raw_result["diagnostics"].append(
            {
                "code": "tool-error",
                "message": str(exc),
            }
        )
        raw_result["partial"] = True
        return normalize_batch_search_decompiled_patterns_result(raw_result)


@register_tool
def list_callsites(
    func: Annotated[str, "目标函数地址或名称"],
    callee_filter: Annotated[str, "Glob 过滤 callee 表达式或 callee 名称"] = "*",
    include_args: Annotated[bool, "是否尽量恢复参数表达式"] = True,
    max_calls: Annotated[int, "最多返回 callsite 数（0=不限制）"] = 0,
) -> dict:
    """List decompiled callsites with best-effort argument and target facts."""
    raw_result: dict[str, Any] = {
        "tool": "list_callsites",
        "function_ea": None,
        "function_name": "",
        "callsites": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays

        function_ea, function_name = _resolve_function(func)
        raw_result["function_ea"] = hex(function_ea)
        raw_result["function_name"] = function_name
        raw_result["raw_name"] = function_name

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            raw_result["diagnostics"].append(
                {
                    "code": "decompile-failed",
                    "message": str(exc),
                }
            )
            raw_result["partial"] = True
            return normalize_list_callsites_result(raw_result)

        if not cfunc:
            raw_result["diagnostics"].append(
                {
                    "code": "decompile-failed",
                    "message": "Decompilation failed",
                }
            )
            raw_result["partial"] = True
            return normalize_list_callsites_result(raw_result)

        raw_result["callsites"] = _list_callsites_from_decompiled_code(
            function_ea=function_ea,
            function_name=function_name,
            code=str(cfunc),
            callee_filter=callee_filter,
            include_args=include_args,
            max_calls=max_calls,
        )
        raw_result["partial"] = any(
            item.get("partial") for item in raw_result["callsites"]
        )
        return normalize_list_callsites_result(raw_result)
    except Exception as exc:
        raw_result["diagnostics"].append(
            {
                "code": "tool-error",
                "message": str(exc),
            }
        )
        raw_result["partial"] = True
        return normalize_list_callsites_result(raw_result)


@register_tool
def extract_function_facts(
    func: Annotated[str, "目标函数地址或名称"],
    filters: Annotated[dict[str, Any], "可选通用过滤参数"] | None = None,
    include_calls: Annotated[bool, "包含 callsite facts"] = True,
    include_accesses: Annotated[bool, "包含 access facts"] = True,
    include_invalidations: Annotated[bool, "包含 invalidation-like facts"] = True,
    include_locks: Annotated[bool, "包含 lock facts"] = True,
) -> dict:
    """Aggregate decompiled function facts without profile-specific verdicts."""
    raw_result: dict[str, Any] = {
        "tool": "extract_function_facts",
        "function_ea": None,
        "function_name": "",
        "calls": [],
        "accesses": [],
        "assignments": [],
        "invalidations": [],
        "locks": [],
        "globals": [],
        "member_fields": [],
        "string_hints": [],
        "symbol_hints": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays

        filters = filters or {}
        function_ea, function_name = _resolve_function(func)
        raw_result["function_ea"] = hex(function_ea)
        raw_result["function_name"] = function_name
        raw_result["raw_name"] = function_name
        raw_result["symbol_hints"] = [function_name] if function_name else []

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            raw_result["diagnostics"].append(
                {
                    "code": "decompile-failed",
                    "message": str(exc),
                }
            )
            raw_result["partial"] = True
            return normalize_extract_function_facts_result(raw_result)

        if not cfunc:
            raw_result["diagnostics"].append(
                {
                    "code": "decompile-failed",
                    "message": "Decompilation failed",
                }
            )
            raw_result["partial"] = True
            return normalize_extract_function_facts_result(raw_result)

        code = str(cfunc)
        callsites: list[dict[str, Any]] = []
        if include_calls or include_invalidations:
            callsites = _list_callsites_from_decompiled_code(
                function_ea=function_ea,
                function_name=function_name,
                code=code,
                callee_filter=str(filters.get("callee_filter", "*")),
                include_args=True,
                max_calls=int(filters.get("max_calls", 0) or 0),
            )
        if include_calls:
            raw_result["calls"] = callsites
        if include_accesses:
            raw_result["accesses"] = _with_access_site_eas(
                function_ea,
                _extract_access_facts_from_code(function_ea, code),
            )
        raw_result["assignments"] = _extract_assignment_facts_from_code(
            function_ea, code
        )
        if include_invalidations:
            raw_result["invalidations"] = _extract_invalidation_facts_from_calls(
                callsites
            ) + _extract_invalidation_facts_from_code(function_ea, code)
        if include_locks:
            raw_result["locks"] = _extract_lock_regions_from_code(
                function_ea,
                code,
                accesses=raw_result["accesses"],
            )

        globals_out, members_out = _function_fact_hints(raw_result["accesses"])
        raw_result["globals"] = globals_out
        raw_result["member_fields"] = members_out
        raw_result["partial"] = (
            any(item.get("partial") for item in raw_result["calls"])
            or any(item.get("partial") for item in raw_result["accesses"])
            or any(item.get("partial") for item in raw_result["invalidations"])
            or any(item.get("partial") for item in raw_result["locks"])
        )
        return normalize_extract_function_facts_result(raw_result)
    except Exception as exc:
        raw_result["diagnostics"].append(
            {
                "code": "tool-error",
                "message": str(exc),
            }
        )
        raw_result["partial"] = True
        return normalize_extract_function_facts_result(raw_result)


_HDF_MICROCODE_INT_RE = re.compile(r"#\s*(0x[0-9A-Fa-f]+|\d{2,})(?:\.\d+)?")
_HDF_MICROCODE_SYMBOL_RE = re.compile(
    r"\b([A-Z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_~<>]*)+|_Z[NTS][A-Za-z0-9_]+)\b"
)
_HDF_MICROCODE_REGISTRATION_MARKERS = (
    "__emplace_unique_key_args",
    "piecewise_construct",
    "operator[]",
    "reqmemberfuncmap",
    "memberfuncmap",
    "requestmap",
    "dispatchmap",
    "std::__",
)
_SELECTOR_DISPATCH_SUPPORTED_PROFILES = {
    "",
    "generic_selector_dispatch",
    "selector_dispatch",
    "std_map_member_function_registration",
    # Backward-compatible spelling for older run configs. The generic tool
    # treats it as an alias and does not call the legacy HDF/RIL tool.
    "hdf_ril_std_map",
}
_SELECTOR_DISPATCH_MICROCODE_REGISTRATION_MARKERS = (
    "__emplace_unique_key_args",
    "piecewise_construct",
    "operator[]",
    "std::map",
    "std::__",
    "unordered_map",
    "emplace",
    "insert",
    "dispatchmap",
    "dispatch_map",
    "requestmap",
    "request_map",
    "callbackmap",
    "callback_map",
    "memberfuncmap",
    "member_func_map",
)
_SELECTOR_DISPATCH_TYPE_ERASURE_MARKERS = (
    "smallhandler",
    "std::any",
    "__any",
    "any_imp",
    "type_info",
)
_SELECTOR_DISPATCH_LOOKBACK_ROWS = 16
_SELECTOR_DISPATCH_LOOKAHEAD_ROWS = 64
_SELECTOR_DISPATCH_MAX_BLOCK_ROWS = 96
_SELECTOR_DISPATCH_GENERIC_NAME_TOKENS = {
    "add",
    "bind",
    "callback",
    "callbacks",
    "cmd",
    "code",
    "command",
    "dispatch",
    "dispatcher",
    "event",
    "ext",
    "handler",
    "handlers",
    "indication",
    "init",
    "install",
    "list",
    "map",
    "message",
    "notification",
    "notify",
    "on",
    "register",
    "registration",
    "report",
    "request",
    "response",
    "selector",
    "table",
    "to",
}
_INDIRECT_CALLSITE_SUPPORTED_PROFILES = {
    "",
    "generic_indirect_callsite",
    "cpp_vtable_callsite",
    "function_pointer_callsite",
}
_INDIRECT_CALLSITE_SLOT_RE = re.compile(
    r"(?:vtable|vftable|vfptr|vptr|_ZTV)[^\n]{0,100}(?:\+|#)\s*(0x[0-9A-Fa-f]+|\d+)"
    r"|\(\s*\*\s*\([^)]*\)\s*[^)\n]{0,120}\+\s*(0x[0-9A-Fa-f]+|\d+)(?:LL)?\s*\)",
    re.IGNORECASE,
)
_INDIRECT_CALLSITE_CALLEE_SLOT_RE = re.compile(
    r"\b(?:icall|calli|mcall)\b[^\n]{0,500}?\[[^\]\n]*?(?:\+|#)\s*(0x[0-9A-Fa-f]+|\d+)(?:\.\d+)?[^\]\n]*\]",
    re.IGNORECASE,
)
_INDIRECT_CALLSITE_VTABLE_SYMBOL_RE = re.compile(
    r"(_ZTV[A-Za-z0-9_]+|[A-Za-z_][A-Za-z0-9_:<>~]*v(?:table|ftable)[A-Za-z0-9_:<>~]*)",
    re.IGNORECASE,
)
_INDIRECT_CALLSITE_VTABLE_MARKERS = ("vtable", "vftable", "_ztv", "vfptr", "vptr")
_PSEUDOCODE_TYPED_VAR_RE = re.compile(
    r"^\s*(?P<type>(?:const\s+)?[A-Za-z_]\w*(?:::[A-Za-z_]\w*|<[^;=()]+>|[\w\s:<>~,])*\s*(?:const\s*)?[*&]+)\s*"
    r"(?P<var>[A-Za-z_]\w*)\b"
)
_PSEUDOCODE_CAST_ASSIGN_RE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*=\s*\((?P<type>[^()]*::[^()]*[*&])\)"
)
_PSEUDOCODE_VPTR_LOAD_RE = re.compile(
    r"\b(?P<vptr>[A-Za-z_]\w*)\s*=\s*\*\s*\([^)]*[*&]\s*\)\s*(?P<receiver>[A-Za-z_]\w*)\b"
)
_PSEUDOCODE_VTABLE_CALL_VPTR_RE = re.compile(
    r"\(\s*(?P<vptr>[A-Za-z_]\w*)\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\s*\)\s*\)\s*"
    r"\((?P<args>[^;]*)\)"
)
_PSEUDOCODE_VTABLE_CALL_DIRECT_RE = re.compile(
    r"\*\s*\([^)]*\)\s*(?P<receiver>[A-Za-z_]\w*)\s*\+\s*(?P<offset>0x[0-9A-Fa-f]+|\d+)\s*\)\s*"
    r"\((?P<args>[^;]*)\)"
)


def _safe_hex_ea(value: Any) -> str | None:
    try:
        number = int(value)
    except Exception:
        return None
    if number < 0:
        return None
    return hex(number)


_MICROCODE_OPCODE_NAMES: dict[int, str] | None = None


def _microcode_opcode_name(opcode: Any) -> str:
    try:
        opcode_int = int(opcode)
    except Exception:
        return ""
    global _MICROCODE_OPCODE_NAMES
    if _MICROCODE_OPCODE_NAMES is None:
        names: dict[int, str] = {}
        try:
            import ida_hexrays

            for attr in dir(ida_hexrays):
                if not attr.startswith("m_"):
                    continue
                try:
                    value = int(getattr(ida_hexrays, attr))
                except Exception:
                    continue
                names.setdefault(value, attr)
        except Exception:
            names = {}
        _MICROCODE_OPCODE_NAMES = names
    return _MICROCODE_OPCODE_NAMES.get(opcode_int, "")


def _microcode_insn_text(insn: Any) -> str:
    dstr = getattr(insn, "dstr", None)
    if callable(dstr):
        try:
            text = str(dstr() or "").strip()
            if text:
                return text
        except Exception:
            pass
    printer = getattr(insn, "_print", None)
    if callable(printer):
        try:
            text = str(printer() or "").strip()
            if text:
                return text
        except Exception:
            pass
    try:
        return str(insn)
    except Exception:
        return repr(insn)


def _microcode_operand_text(value: Any) -> str:
    if value is None:
        return ""
    dstr = getattr(value, "dstr", None)
    if callable(dstr):
        try:
            text = str(dstr() or "").strip()
            if text:
                return text
        except Exception:
            pass
    try:
        return str(value)
    except Exception:
        return repr(value)


def _microcode_row_text(row: dict[str, Any]) -> str:
    parts = [str(row.get("text") or "")]
    parts.extend(
        str(item) for item in row.get("operands") or [] if str(item or "").strip()
    )
    return " ".join(parts)


def _microcode_preview_text(value: Any, limit: int = 800) -> str:
    text = str(value or "")
    max_len = max(80, int(limit or 800))
    if len(text) <= max_len:
        return text
    return text[:max_len] + "...[truncated]"


def _parse_hdf_microcode_int(value: str) -> int | None:
    try:
        return int(str(value), 0)
    except Exception:
        return None


def _ida_function_symbol_display_name(raw_name: str, demangled_name: str) -> str:
    demangled = str(demangled_name or "").strip()
    if demangled:
        return demangled
    components = _selector_dispatch_itanium_nested_components(raw_name)
    if components:
        return "::".join(components)
    return str(raw_name or "").strip()


def _ida_function_symbol_short_name(display_name: str, raw_name: str) -> str:
    display = str(display_name or "").strip()
    if display:
        return display.split("::")[-1].split("(", 1)[0]
    return str(raw_name or "").strip()


def _list_ida_function_symbols() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    try:
        import ida_funcs
        import ida_name
        import idautils
        import idc
    except Exception:
        return entries

    for ea in idautils.Functions():
        raw_name = ida_funcs.get_func_name(ea) or ida_name.get_name(ea) or ""
        demangled = ""
        if raw_name:
            try:
                demangled = (
                    idc.demangle_name(raw_name, idc.get_inf_attr(idc.INF_SHORT_DN))
                    or ""
                )
            except Exception:
                demangled = ""
        components = _selector_dispatch_itanium_nested_components(raw_name)
        itanium_display_name = "::".join(components) if components else ""
        display_name = _ida_function_symbol_display_name(raw_name, demangled)
        entries.append(
            {
                "ea": hex(int(ea)),
                "name": raw_name,
                "demangled_name": display_name,
                "itanium_display_name": itanium_display_name,
                "short_name": _ida_function_symbol_short_name(display_name, raw_name),
            }
        )
    return entries


def _int_from_hex_text(value: Any) -> int | None:
    token = str(value or "").strip()
    if not token:
        return None
    try:
        return int(token, 0)
    except Exception:
        return None


def _ida_pointer_size() -> int:
    try:
        import ida_ida

        return 8 if ida_ida.inf_is_64bit() else 4
    except Exception:
        return 8


def _read_ida_pointer(ea: int, pointer_size: int) -> int | None:
    try:
        import ida_bytes

        if pointer_size == 8:
            value = int(ida_bytes.get_qword(ea))
        else:
            value = int(ida_bytes.get_dword(ea))
    except Exception:
        return None
    if value <= 0:
        return None
    return value


def _vtable_class_name(raw_name: str, demangled_name: str) -> str:
    demangled = str(demangled_name or "").strip()
    if demangled.startswith("vtable for "):
        return demangled[len("vtable for ") :].strip()
    raw = str(raw_name or "").strip()
    components = (
        _selector_dispatch_itanium_nested_components(raw.replace("_ZTV", "_ZN", 1))
        if raw.startswith("_ZTV")
        else []
    )
    if components:
        return "::".join(components)
    return demangled or raw


def _vtable_symbol_tokens(entry: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for key in ("vtable_symbol", "vtable_demangled_name", "class_name"):
        token = str(entry.get(key) or "").strip()
        if token and token not in tokens:
            tokens.append(token)
    return tokens


def _class_context_tokens_for_vtable_entry(
    vtable_entry: dict[str, Any],
    class_prefixes: list[str],
) -> list[str]:
    tokens: list[str] = []
    for token in [*_vtable_symbol_tokens(vtable_entry), *class_prefixes]:
        token = str(token or "").strip()
        if not token:
            continue
        for candidate in (
            token,
            token.replace("`vtable for'", "").replace("vtable for ", "").strip(),
        ):
            if candidate and candidate not in tokens:
                tokens.append(candidate)
            if "::" in candidate:
                tail = candidate.rsplit("::", 1)[-1].split("<", 1)[0].strip()
                if tail and tail not in tokens:
                    tokens.append(tail)
        raw = token
        if raw.startswith("_ZTV"):
            components = _selector_dispatch_itanium_nested_components(
                raw.replace("_ZTV", "_ZN", 1)
            )
            if components:
                qualified = "::".join(components)
                if qualified and qualified not in tokens:
                    tokens.append(qualified)
                tail = components[-1]
                if tail and tail not in tokens:
                    tokens.append(tail)
    return tokens


def _list_ida_vtable_slot_entries(
    function_symbols: list[dict[str, Any]], max_entries_per_vtable: int = 128
) -> list[dict[str, Any]]:
    """Return concrete vtable slot entries backed by IDA names and data bytes."""

    try:
        import idautils
        import idc
    except Exception:
        return []

    functions_by_ea: dict[int, dict[str, Any]] = {}
    for symbol in function_symbols or []:
        ea = _int_from_hex_text(symbol.get("ea"))
        if ea is not None:
            functions_by_ea[ea] = dict(symbol)

    pointer_size = _ida_pointer_size()
    entries: list[dict[str, Any]] = []
    seen: set[tuple[int, int, int]] = set()
    for ea, raw_name in idautils.Names():
        raw = str(raw_name or "")
        demangled = ""
        if raw:
            try:
                demangled = (
                    idc.demangle_name(raw, idc.get_inf_attr(idc.INF_SHORT_DN)) or ""
                )
            except Exception:
                demangled = ""
        if "_ZTV" not in raw and not str(demangled).startswith("vtable for "):
            continue
        class_name = _vtable_class_name(raw, demangled)
        for index in range(max(0, int(max_entries_per_vtable or 128))):
            slot_ea = int(ea) + index * pointer_size
            target_ea = _read_ida_pointer(slot_ea, pointer_size)
            if target_ea is None:
                continue
            target = functions_by_ea.get(target_ea)
            if not target:
                continue
            key = (int(ea), index, target_ea)
            if key in seen:
                continue
            seen.add(key)
            raw_offset = index * pointer_size
            address_point_adjusted_offset = raw_offset - (2 * pointer_size)
            entries.append(
                {
                    "vtable_ea": hex(int(ea)),
                    "vtable_symbol": raw,
                    "vtable_demangled_name": demangled,
                    "class_name": class_name,
                    "slot_index": index,
                    "itanium_slot_index": index - 2,
                    "vtable_entry_offset": hex(raw_offset),
                    "address_point_adjusted_offset": (
                        hex(address_point_adjusted_offset)
                        if address_point_adjusted_offset >= 0
                        else ""
                    ),
                    "target_ea": hex(target_ea),
                    "target_function": str(
                        target.get("name") or target.get("demangled_name") or ""
                    ),
                    "target_demangled_name": str(target.get("demangled_name") or ""),
                    "target_short_name": str(target.get("short_name") or ""),
                    "pointer_size": pointer_size,
                }
            )
    return entries


def _vtable_entry_filter_match(
    entry: dict[str, Any],
    *,
    class_prefixes: list[str],
    target_functions: list[str],
    slot_offsets: set[int],
) -> bool:
    tokens = _vtable_symbol_tokens(entry)
    target_tokens = [
        str(entry.get("target_ea") or ""),
        str(entry.get("target_function") or ""),
        str(entry.get("target_demangled_name") or ""),
        str(entry.get("target_short_name") or ""),
    ]
    if class_prefixes and not any(
        prefix and any(prefix in token for token in tokens) for prefix in class_prefixes
    ):
        return False
    if target_functions and not any(
        requested
        and any(
            requested == token or requested in token or token in requested
            for token in target_tokens
        )
        for requested in target_functions
    ):
        return False
    if slot_offsets:
        offsets = {
            _int_from_hex_text(entry.get("vtable_entry_offset")),
            _int_from_hex_text(entry.get("address_point_adjusted_offset")),
        }
        offsets.discard(None)
        if not any(int(offset) in slot_offsets for offset in offsets):
            return False
    return True


def _normalize_type_hint(value: str) -> str:
    token = str(value or "").strip()
    token = re.sub(r"\b(const|volatile|struct|class)\b", "", token)
    token = token.replace("*", "").replace("&", "").strip()
    return re.sub(r"\s+", " ", token)


def _receiver_type_allowed(
    receiver_type: str, receiver_type_prefixes: list[str]
) -> bool:
    if not receiver_type_prefixes:
        return True
    normalized = _normalize_type_hint(receiver_type)
    return any(prefix and prefix in normalized for prefix in receiver_type_prefixes)


def _first_argument(args_text: str) -> str:
    args = _split_arguments(str(args_text or ""))
    if not args:
        return ""
    match = re.search(r"\b([A-Za-z_]\w*)\b", args[0])
    return match.group(1) if match else ""


def _pseudocode_type_hints(lines: list[str]) -> dict[str, str]:
    hints: dict[str, str] = {}
    for line in lines:
        declaration = _PSEUDOCODE_TYPED_VAR_RE.search(line)
        if declaration:
            hints[declaration.group("var")] = _normalize_type_hint(
                declaration.group("type")
            )
        cast_assignment = _PSEUDOCODE_CAST_ASSIGN_RE.search(line)
        if cast_assignment:
            hints[cast_assignment.group("var")] = _normalize_type_hint(
                cast_assignment.group("type")
            )
    return hints


def _pseudocode_vptr_receivers(lines: list[str]) -> dict[str, str]:
    receivers: dict[str, str] = {}
    for line in lines:
        match = _PSEUDOCODE_VPTR_LOAD_RE.search(line)
        if match:
            receivers[match.group("vptr")] = match.group("receiver")
    return receivers


def _vtable_callsites_from_decompiled_code(
    *,
    code: str,
    dispatch_so: str,
    caller_function: str,
    caller_ea: str,
    receiver_type_prefixes: list[str],
    slot_offsets: set[int],
    max_callsites: int = 64,
) -> list[dict[str, Any]]:
    lines = str(code or "").splitlines()
    type_hints = _pseudocode_type_hints(lines)
    vptr_receivers = _pseudocode_vptr_receivers(lines)
    callsites: list[dict[str, Any]] = []
    seen: set[tuple[int, str, int, str]] = set()
    max_count = max(1, int(max_callsites or 64))
    for line_no, line in enumerate(lines, start=1):
        matches = list(_PSEUDOCODE_VTABLE_CALL_VPTR_RE.finditer(line))
        matches.extend(_PSEUDOCODE_VTABLE_CALL_DIRECT_RE.finditer(line))
        for match in matches:
            offset = _int_from_hex_text(match.group("offset"))
            if offset is None:
                continue
            if slot_offsets and offset not in slot_offsets:
                continue
            args = str(match.group("args") or "")
            vptr = str(match.groupdict().get("vptr") or "")
            receiver = str(match.groupdict().get("receiver") or "")
            receiver = receiver or vptr_receivers.get(vptr, "") or _first_argument(args)
            receiver_type = type_hints.get(receiver, "")
            if not _receiver_type_allowed(receiver_type, receiver_type_prefixes):
                continue
            key = (line_no, receiver, offset, line.strip())
            if key in seen:
                continue
            seen.add(key)
            callsites.append(
                {
                    "kind": "vtable_callsite",
                    "dispatch_so": dispatch_so,
                    "dispatch_function": caller_function,
                    "caller_ea": caller_ea,
                    "line_no": line_no,
                    "line_text": _microcode_preview_text(line.strip(), 1200),
                    "slot_offset": hex(offset),
                    "slot_offset_int": offset,
                    "receiver_expr": receiver,
                    "receiver_type": receiver_type,
                    "receiver_type_source": (
                        "pseudocode-local-type" if receiver_type else ""
                    ),
                    "vptr_expr": vptr,
                    "confidence": 0.82 if receiver_type else 0.74,
                    "provenance": {
                        "source": "decompile",
                        "pattern": "pseudocode_cpp_vtable_callsite",
                        "exact_callsite_observed": True,
                        "dispatch_slot_observed": True,
                        "exact_vtable_slot_observed": False,
                    },
                }
            )
            if len(callsites) >= max_count:
                return callsites
    return callsites


def _resolve_hdf_microcode_symbol(
    symbol: str, function_symbols: list[dict[str, Any]]
) -> str:
    token = str(symbol or "").strip()
    if not token:
        return ""
    short = token.split("::")[-1]
    for entry in function_symbols:
        if token in {entry.get("name"), entry.get("demangled_name")}:
            return str(entry.get("name") or token)
    for entry in function_symbols:
        if short and short in {entry.get("short_name"), entry.get("name")}:
            return str(entry.get("name") or token)
    for entry in function_symbols:
        demangled = str(entry.get("demangled_name") or "")
        name = str(entry.get("name") or "")
        if short and (short in demangled or short in name):
            return name or token
    return token


def _hdf_handler_from_microcode_window(
    window_text: str, function_symbols: list[dict[str, Any]], current_function: str
) -> str:
    ignored_suffixes = {
        "",
        current_function.split("::")[-1],
        "__emplace_unique_key_args",
        "piecewise_construct",
        "operator",
        "operator[]",
    }
    matches = [
        match.group(1) for match in _HDF_MICROCODE_SYMBOL_RE.finditer(window_text)
    ]
    preferred = [
        item
        for item in matches
        if item.startswith("_ZN4OHOS") or item.startswith("OHOS::")
    ]
    for candidate in preferred + matches:
        lowered = candidate.lower()
        short = candidate.split("::")[-1]
        if short in ignored_suffixes:
            continue
        if lowered.startswith("std::") or "::__" in candidate or "__h::" in candidate:
            continue
        if (
            lowered.startswith("_znst")
            or "smallhandler" in lowered
            or "__any_imp" in lowered
            or "type_info" in lowered
        ):
            continue
        resolved = _resolve_hdf_microcode_symbol(candidate, function_symbols)
        if resolved:
            return resolved
    return ""


def _hdf_selector_candidates_from_microcode_window(window_text: str) -> list[int]:
    selectors: list[int] = []
    for match in _HDF_MICROCODE_INT_RE.finditer(window_text):
        value = _parse_hdf_microcode_int(match.group(1))
        if value is None:
            continue
        if value == 0 or value < 256:
            continue
        if value > 0xFFFF:
            continue
        selectors.append(value)
    return list(dict.fromkeys(selectors))


def _hdf_selector_allowed(
    selector: int,
    expected_selectors: set[int],
    selector_min: int | None,
    selector_max: int | None,
) -> bool:
    if expected_selectors and selector not in expected_selectors:
        return False
    if selector_min is not None and selector < selector_min:
        return False
    if selector_max is not None and selector > selector_max:
        return False
    return True


def _hdf_handler_allowed(handler: str, handler_prefixes: list[str]) -> bool:
    if not handler_prefixes:
        return True
    return any(
        handler.startswith(prefix) or prefix in handler for prefix in handler_prefixes
    )


def _selector_dispatch_profile(value: Any) -> str:
    normalized = str(value or "generic_selector_dispatch").strip()
    if normalized in {"", "hdf_ril_std_map"}:
        return "generic_selector_dispatch"
    return normalized


def _selector_dispatch_symbol_tokens(symbol: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for key in ("name", "demangled_name", "itanium_display_name", "short_name"):
        token = str(symbol.get(key) or "").strip()
        if token and token not in tokens:
            tokens.append(token)
    return tokens


def _selector_dispatch_itanium_nested_components(name: str) -> list[str]:
    text = str(name or "").strip()
    if not text.startswith("_ZN"):
        return []
    index = 3
    components: list[str] = []
    while index < len(text) and text[index] != "E":
        length_start = index
        while index < len(text) and text[index].isdigit():
            index += 1
        if index == length_start:
            break
        try:
            length = int(text[length_start:index])
        except ValueError:
            break
        if length <= 0 or index + length > len(text):
            break
        components.append(text[index : index + length])
        index += length
    return components


def _selector_dispatch_itanium_family_prefix(name: str) -> str:
    components = _selector_dispatch_itanium_nested_components(name)
    if len(components) < 2:
        return ""
    return "_ZN" + "".join(
        f"{len(component)}{component}" for component in components[:-1]
    )


def _selector_dispatch_demangled_family_prefix(name: str) -> str:
    text = str(name or "").strip()
    if "::" not in text:
        return ""
    head = text.split("(", 1)[0].strip()
    parts = [part for part in head.split("::") if part]
    if len(parts) < 2:
        return ""
    return "::".join(parts[:-1]) + "::"


def _selector_dispatch_symbol_entry_for_function(
    function_name: str,
    function_symbols: list[dict[str, Any]],
) -> dict[str, Any]:
    target = str(function_name or "").strip()
    if not target:
        return {}
    for entry in function_symbols:
        if target in _selector_dispatch_symbol_tokens(entry):
            return entry
    for entry in function_symbols:
        if target == str(entry.get("name") or ""):
            return entry
    return {}


def _selector_dispatch_infer_handler_family_hints(
    function_name: str,
    function_symbols: list[dict[str, Any]],
) -> list[str]:
    hints: list[str] = []
    entry = _selector_dispatch_symbol_entry_for_function(
        function_name, function_symbols
    )
    tokens = (
        _selector_dispatch_symbol_tokens(entry) if entry else [str(function_name or "")]
    )
    for token in tokens:
        for hint in (
            _selector_dispatch_itanium_family_prefix(token),
            _selector_dispatch_demangled_family_prefix(token),
        ):
            if hint and hint not in hints:
                hints.append(hint)
    return hints


def _selector_dispatch_runtime_symbol(token: str, current_function: str) -> bool:
    lowered = token.lower()
    short = token.split("::")[-1]
    current_short = current_function.split("::")[-1]
    if not token or token == current_function or short == current_short:
        return True
    if (
        lowered.startswith(("std::", "__gnu_cxx::"))
        or "::__" in token
        or "__h::" in token
    ):
        return True
    if lowered.startswith(("_znst", "_zst")):
        return True
    if any(
        marker in lowered
        for marker in ("piecewise_construct", "__emplace", "operator[]", "type_info")
    ):
        return True
    if any(marker in lowered for marker in _SELECTOR_DISPATCH_TYPE_ERASURE_MARKERS):
        return True
    return False


def _selector_dispatch_handler_allowed_by_prefix(
    tokens: list[str], handler_prefixes: list[str]
) -> bool:
    if not handler_prefixes:
        return True
    return any(
        token.startswith(prefix) or prefix in token
        for token in tokens
        for prefix in handler_prefixes
    )


def _selector_dispatch_handler_allowed(
    tokens: list[str],
    *,
    handler_prefixes: list[str],
    target_functions: list[str],
) -> bool:
    if target_functions:
        return any(
            target == token or target in token or token in target
            for token in tokens
            for target in target_functions
            if token and target
        )
    return _selector_dispatch_handler_allowed_by_prefix(tokens, handler_prefixes)


def _selector_dispatch_has_registration_marker(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(
        marker.lower() in lowered
        for marker in _SELECTOR_DISPATCH_MICROCODE_REGISTRATION_MARKERS
    )


def _selector_dispatch_has_type_erasure_marker(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in _SELECTOR_DISPATCH_TYPE_ERASURE_MARKERS)


def _selector_dispatch_selector_row_indexes(
    rows: list[dict[str, Any]],
    *,
    expected_selectors: set[int],
    selector_min: int | None,
    selector_max: int | None,
) -> list[int]:
    indexes: list[int] = []
    for index, row in enumerate(rows):
        row_selectors = [
            selector
            for selector in _hdf_selector_candidates_from_microcode_window(
                _microcode_row_text(row)
            )
            if _hdf_selector_allowed(
                selector, expected_selectors, selector_min, selector_max
            )
        ]
        if row_selectors:
            indexes.append(index)
    return indexes


def _selector_dispatch_registration_window_bounds(
    rows: list[dict[str, Any]],
    selector_index: int,
    *,
    expected_selectors: set[int] | None = None,
    selector_min: int | None = None,
    selector_max: int | None = None,
) -> tuple[int, int]:
    row_count = len(rows)
    start = max(0, selector_index - _SELECTOR_DISPATCH_LOOKBACK_ROWS)
    end = min(row_count, selector_index + _SELECTOR_DISPATCH_LOOKAHEAD_ROWS + 1)
    selector_indexes = _selector_dispatch_selector_row_indexes(
        rows,
        expected_selectors=expected_selectors or set(),
        selector_min=selector_min,
        selector_max=selector_max,
    )
    previous_selectors = [index for index in selector_indexes if index < selector_index]
    next_selectors = [index for index in selector_indexes if index > selector_index]
    if previous_selectors:
        start = max(start, max(previous_selectors) + 1)
    if next_selectors:
        end = min(end, min(next_selectors))
    block_start = start
    block_end = end
    marker_indexes: list[int] = []
    for index in range(start, end):
        if _selector_dispatch_has_registration_marker(_microcode_row_text(rows[index])):
            marker_indexes.append(index)
    if marker_indexes:
        start = min(selector_index, min(marker_indexes))
        end = min(
            row_count,
            max(selector_index, max(marker_indexes))
            + _SELECTOR_DISPATCH_LOOKAHEAD_ROWS
            + 1,
        )
        start = max(start, block_start)
        end = min(end, block_end)
    if end - start > _SELECTOR_DISPATCH_MAX_BLOCK_ROWS:
        start = max(0, selector_index - _SELECTOR_DISPATCH_LOOKBACK_ROWS)
        end = min(row_count, start + _SELECTOR_DISPATCH_MAX_BLOCK_ROWS)
        if selector_index >= end:
            end = min(row_count, selector_index + _SELECTOR_DISPATCH_LOOKAHEAD_ROWS + 1)
            start = max(0, end - _SELECTOR_DISPATCH_MAX_BLOCK_ROWS)
    return start, end


def _selector_dispatch_split_words(value: str) -> list[str]:
    words: list[str] = []
    for chunk in re.split(r"[^A-Za-z0-9]+", str(value or "")):
        if not chunk:
            continue
        for word in re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z]?[a-z]+|\d+", chunk):
            token = word.lower()
            if token and token not in words:
                words.append(token)
    return words


def _selector_dispatch_name_terms(value: str) -> set[str]:
    components = _selector_dispatch_itanium_nested_components(str(value or "")) or [
        str(value or "")
    ]
    terms: set[str] = set()
    for component in components:
        words = [
            word
            for word in _selector_dispatch_split_words(component)
            if word and word not in _SELECTOR_DISPATCH_GENERIC_NAME_TOKENS
        ]
        terms.update(words)
        if len(words) >= 2:
            initials = "".join(word[:1] for word in words if word)
            if len(initials) >= 2:
                terms.add(initials)
            for index in range(0, len(words) - 1):
                pair = "".join(word[:1] for word in words[index : index + 2] if word)
                if len(pair) >= 2:
                    terms.add(pair)
    return {term for term in terms if term}


def _selector_dispatch_terms_overlap(left: set[str], right: set[str]) -> bool:
    if left & right:
        return True
    for left_term in left:
        for right_term in right:
            if len(left_term) >= 3 and left_term in right_term:
                return True
            if len(right_term) >= 3 and right_term in left_term:
                return True
    return False


def _selector_dispatch_compatible_dispatch_functions(
    dispatch_functions: list[str],
    *,
    registration_function: str,
    target_function: str,
) -> list[str]:
    right_terms = _selector_dispatch_name_terms(
        registration_function
    ) | _selector_dispatch_name_terms(target_function)
    if not right_terms:
        return []
    compatible: list[str] = []
    for dispatch_function in dispatch_functions:
        dispatch = str(dispatch_function or "").strip()
        if not dispatch:
            continue
        dispatch_terms = _selector_dispatch_name_terms(dispatch)
        if dispatch_terms and _selector_dispatch_terms_overlap(
            dispatch_terms, right_terms
        ):
            compatible.append(dispatch)
    return compatible


def _selector_dispatch_symbol_observation(
    entry: dict[str, Any],
    *,
    window_text: str,
    current_function: str,
    handler_prefixes: list[str],
    target_functions: list[str],
) -> dict[str, Any] | None:
    tokens = _selector_dispatch_symbol_tokens(entry)
    evidence_token = next(
        (token for token in tokens if token and token in window_text), ""
    )
    if not evidence_token:
        return None
    if any(
        _selector_dispatch_runtime_symbol(token, current_function) for token in tokens
    ):
        return None
    if not _selector_dispatch_handler_allowed(
        tokens,
        handler_prefixes=handler_prefixes,
        target_functions=target_functions,
    ):
        return None
    return {
        "handler": str(
            entry.get("name") or entry.get("demangled_name") or evidence_token
        ),
        "evidence_kind": "ida-function-symbol",
        "evidence_token": evidence_token,
    }


def _selector_dispatch_handler_observation_from_microcode_window(
    window_text: str,
    function_symbols: list[dict[str, Any]],
    current_function: str,
    handler_prefixes: list[str],
    target_functions: list[str],
) -> dict[str, Any] | None:
    symbols_by_weight = sorted(
        function_symbols,
        key=lambda item: max(
            (len(token) for token in _selector_dispatch_symbol_tokens(item)), default=0
        ),
        reverse=True,
    )
    for entry in symbols_by_weight:
        observation = _selector_dispatch_symbol_observation(
            entry,
            window_text=window_text,
            current_function=current_function,
            handler_prefixes=handler_prefixes,
            target_functions=target_functions,
        )
        if observation is not None:
            return observation

    matches = [
        match.group(1) for match in _HDF_MICROCODE_SYMBOL_RE.finditer(window_text)
    ]
    for candidate in matches:
        if _selector_dispatch_runtime_symbol(candidate, current_function):
            continue
        resolved = _resolve_hdf_microcode_symbol(candidate, function_symbols)
        tokens = [candidate, resolved]
        if not _selector_dispatch_handler_allowed(
            tokens,
            handler_prefixes=handler_prefixes,
            target_functions=target_functions,
        ):
            continue
        return {
            "handler": resolved,
            "evidence_kind": "microcode-symbol-token",
            "evidence_token": candidate,
        }
    return None


def _selector_dispatch_handler_from_microcode_window(
    window_text: str,
    function_symbols: list[dict[str, Any]],
    current_function: str,
    handler_prefixes: list[str],
    target_functions: list[str],
) -> str:
    observation = _selector_dispatch_handler_observation_from_microcode_window(
        window_text,
        function_symbols,
        current_function,
        handler_prefixes,
        target_functions,
    )
    if observation:
        return str(observation.get("handler") or "")
    return ""


def _hdf_int_set(values: Any) -> set[int]:
    result: set[int] = set()
    for item in normalize_list_input(values):
        try:
            result.add(int(str(item), 0))
        except Exception:
            continue
    return result


def _hdf_registration_facts_from_microcode_rows(
    *,
    rows: list[dict[str, Any]],
    from_so: str,
    dispatcher_function: str,
    registration_function: str,
    function_symbols: list[dict[str, Any]],
    expected_selectors: set[int] | None = None,
    selector_min: int | None = None,
    selector_max: int | None = None,
    handler_prefixes: list[str] | None = None,
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    seen_selectors: set[int] = set()
    expected_selectors = expected_selectors or set()
    handler_prefixes = handler_prefixes or []
    for index, row in enumerate(rows):
        row_text = _microcode_row_text(row)
        row_selectors = [
            selector
            for selector in _hdf_selector_candidates_from_microcode_window(row_text)
            if _hdf_selector_allowed(
                selector, expected_selectors, selector_min, selector_max
            )
        ]
        if not row_selectors:
            continue
        start = max(0, index - 12)
        end = min(len(rows), index + 28)
        window_rows = rows[start:end]
        window_text = "\n".join(_microcode_row_text(item) for item in window_rows)
        lowered_window = window_text.lower()
        if not any(
            marker in lowered_window for marker in _HDF_MICROCODE_REGISTRATION_MARKERS
        ):
            continue
        handler = _hdf_handler_from_microcode_window(
            window_text, function_symbols, registration_function
        )
        if not handler:
            continue
        if not _hdf_handler_allowed(handler, handler_prefixes):
            continue
        for selector in row_selectors:
            if selector in seen_selectors:
                continue
            seen_selectors.add(selector)
            facts.append(
                {
                    "kind": "hdf_dispatch_entry",
                    "from_so": from_so,
                    "from_function": dispatcher_function or registration_function,
                    "to_so": from_so,
                    "to_function": handler,
                    "selector": selector,
                    "confidence": 0.90,
                    "provenance": {
                        "source": "microcode",
                        "pattern": "microcode_std_map_member_function_registration",
                        "registration_function": registration_function,
                        "microcode_row": index,
                        "function_ea": row.get("function_ea"),
                        "site_ea": row.get("ea"),
                    },
                }
            )
    return facts


def _selector_dispatch_facts_from_microcode_rows(
    *,
    rows: list[dict[str, Any]],
    dispatch_so: str,
    dispatch_function: str,
    dispatch_functions: list[str] | None = None,
    registration_function: str,
    function_symbols: list[dict[str, Any]],
    expected_selectors: set[int] | None = None,
    selector_min: int | None = None,
    selector_max: int | None = None,
    handler_prefixes: list[str] | None = None,
    target_functions: list[str] | None = None,
    extractor_profile: str = "generic_selector_dispatch",
    emit_registration_partial: bool = False,
    diagnostics_out: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    facts: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    expected_selectors = expected_selectors or set()
    handler_prefixes = handler_prefixes or []
    target_functions = [
        str(item).strip() for item in list(target_functions or []) if str(item).strip()
    ]
    profile = _selector_dispatch_profile(extractor_profile)

    for index, row in enumerate(rows):
        row_text = _microcode_row_text(row)
        row_selectors = [
            selector
            for selector in _hdf_selector_candidates_from_microcode_window(row_text)
            if _hdf_selector_allowed(
                selector, expected_selectors, selector_min, selector_max
            )
        ]
        if not row_selectors:
            continue
        start, end = _selector_dispatch_registration_window_bounds(
            rows,
            index,
            expected_selectors=expected_selectors,
            selector_min=selector_min,
            selector_max=selector_max,
        )
        window_rows = rows[start:end]
        window_text = "\n".join(_microcode_row_text(item) for item in window_rows)
        has_registration_marker = _selector_dispatch_has_registration_marker(
            window_text
        )
        if not has_registration_marker:
            continue
        handler_observation = (
            _selector_dispatch_handler_observation_from_microcode_window(
                window_text,
                function_symbols,
                registration_function,
                handler_prefixes,
                target_functions,
            )
        )
        if not handler_observation:
            if (
                diagnostics_out is not None
                and _selector_dispatch_has_type_erasure_marker(window_text)
            ):
                diagnostics_out.append(
                    {
                        "code": "unresolved_type_erased_member_function_registration",
                        "message": (
                            "selector registration uses type-erased/member-function wrapper, "
                            "but no concrete handler symbol was observed"
                        ),
                        "registration_function": registration_function,
                        "selectors": row_selectors,
                        "microcode_row": index,
                        "site_ea": row.get("ea"),
                        "window_start": start,
                        "window_end": end,
                    }
                )
            continue
        handler = str(handler_observation.get("handler") or "")
        if not handler:
            continue
        compatible_dispatch_functions = (
            _selector_dispatch_compatible_dispatch_functions(
                list(
                    dispatch_functions
                    or ([dispatch_function] if dispatch_function else [])
                ),
                registration_function=registration_function,
                target_function=handler,
            )
        )
        for selector in row_selectors:
            key = (selector, handler)
            if key in seen:
                continue
            seen.add(key)
            provenance = {
                "source": "microcode",
                "pattern": "microcode_selector_dispatch_registration",
                "extractor_profile": profile,
                "registration_function": registration_function,
                "microcode_row": index,
                "function_ea": row.get("function_ea"),
                "site_ea": row.get("ea"),
                "registration_marker_observed": has_registration_marker,
                "handler_evidence_kind": handler_observation.get("evidence_kind"),
                "handler_evidence_token": handler_observation.get("evidence_token"),
                "window_start": start,
                "window_end": end,
            }
            registration_fact = {
                "kind": (
                    "selector_dispatch_registration"
                    if emit_registration_partial
                    else "selector_dispatch_entry"
                ),
                "target_so": dispatch_so,
                "target_function": handler,
                "selector": selector,
                "selector_source": "registration-key",
                "confidence": 0.90 if has_registration_marker else 0.82,
                "provenance": provenance,
            }
            if emit_registration_partial:
                registration_fact["registration_function"] = registration_function
            else:
                registration_fact["dispatch_so"] = dispatch_so
                registration_fact["dispatch_function"] = (
                    dispatch_function or registration_function
                )
            facts.append(registration_fact)
            if emit_registration_partial:
                for compatible_dispatch_function in compatible_dispatch_functions:
                    entry = dict(registration_fact)
                    entry["kind"] = "selector_dispatch_entry"
                    entry["dispatch_so"] = dispatch_so
                    entry["dispatch_function"] = compatible_dispatch_function
                    entry["confidence"] = min(
                        float(entry.get("confidence") or 0.90), 0.86
                    )
                    entry_provenance = dict(provenance)
                    entry_provenance["pattern"] = (
                        "microcode_selector_dispatch_registration_with_dispatch_scope"
                    )
                    entry_provenance["dispatch_function"] = compatible_dispatch_function
                    entry_provenance["registration_partial_kind"] = (
                        "selector_dispatch_registration"
                    )
                    entry["provenance"] = entry_provenance
                    facts.append(entry)
    return facts


def _canonical_selector_dispatch_entry_from_hdf_fact(
    fact: dict[str, Any],
) -> dict[str, Any]:
    """Convert the HDF/RIL validation fact shape to the generic raw schema."""

    raw = dict(fact or {})
    provenance = dict(raw.get("provenance") or {})
    raw_kind = str(raw.get("kind") or "").strip()
    if raw_kind and raw_kind != "selector_dispatch_entry":
        provenance.setdefault("raw_kind", raw_kind)
    provenance.setdefault("source", "microcode")
    return {
        "kind": "selector_dispatch_entry",
        "dispatch_so": str(raw.get("dispatch_so") or raw.get("from_so") or ""),
        "dispatch_function": str(
            raw.get("dispatch_function") or raw.get("from_function") or ""
        ),
        "target_so": str(raw.get("target_so") or raw.get("to_so") or ""),
        "target_function": str(
            raw.get("target_function") or raw.get("to_function") or ""
        ),
        "selector": raw.get("selector"),
        "selector_source": str(
            raw.get("selector_source") or raw.get("selector_arg") or "selector"
        ),
        "confidence": raw.get("confidence", 0.9),
        "provenance": provenance,
    }


def _indirect_callsite_profile(value: Any) -> str:
    normalized = str(value or "generic_indirect_callsite").strip()
    return normalized or "generic_indirect_callsite"


def _indirect_callsite_target_entries(
    *,
    function_symbols: list[dict[str, Any]],
    target_functions: Any = "",
    target_method_names: Any = "",
    class_prefixes: Any = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve a bounded target allow-list into symbol entries.

    This extractor is intentionally target-scoped.  It should prove a concrete
    semantic edge requested by a higher-level profile, not enumerate every
    indirect call in a large binary.
    """

    requested_targets = [
        str(item).strip()
        for item in normalize_list_input(target_functions)
        if str(item).strip()
    ]
    requested_methods = [
        str(item).strip()
        for item in normalize_list_input(target_method_names)
        if str(item).strip()
    ]
    prefixes = [
        str(item).strip()
        for item in normalize_list_input(class_prefixes)
        if str(item).strip()
    ]
    diagnostics: list[dict[str, Any]] = []
    if not requested_targets and not (requested_methods and prefixes):
        diagnostics.append(
            {
                "code": "target-filter-required",
                "message": (
                    "target_functions or target_method_names plus class_prefixes is required; "
                    "broad indirect-callsite enumeration is intentionally disabled"
                ),
            }
        )
        return [], diagnostics

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for symbol in function_symbols:
        raw_entry = dict(symbol or {})
        tokens = _selector_dispatch_symbol_tokens(raw_entry)
        ea = str(raw_entry.get("ea") or "").strip()
        short_name = str(raw_entry.get("short_name") or "").strip()
        target_match = any(
            requested
            and (
                requested == ea
                or any(requested == token or requested in token for token in tokens)
            )
            for requested in requested_targets
        )
        method_match = (
            bool(requested_methods and prefixes)
            and short_name in requested_methods
            and any(
                prefix and any(prefix in token for token in tokens)
                for prefix in prefixes
            )
        )
        if not target_match and not method_match:
            continue
        key = str(
            raw_entry.get("name") or raw_entry.get("demangled_name") or ea or tokens[0]
        )
        if key in seen:
            continue
        seen.add(key)
        raw_entry["_target_match_kind"] = (
            "target_function" if target_match else "class_scoped_method"
        )
        entries.append(raw_entry)

    unresolved = []
    for requested in requested_targets:
        if any(
            requested == str(entry.get("ea") or "")
            or requested in _selector_dispatch_symbol_tokens(entry)
            or any(
                requested in token for token in _selector_dispatch_symbol_tokens(entry)
            )
            for entry in entries
        ):
            continue
        unresolved.append(requested)
        synthetic = {
            "ea": "",
            "name": requested,
            "demangled_name": "",
            "short_name": requested.split("::")[-1],
            "_target_match_kind": "requested_symbol",
            "_synthetic_target": True,
        }
        key = requested
        if key not in seen:
            seen.add(key)
            entries.append(synthetic)
    if unresolved:
        diagnostics.append(
            {
                "code": "target-symbol-not-in-function-list",
                "targets": unresolved,
                "message": "requested target symbol was not present in the IDA function list; matching uses the requested token only",
            }
        )
    return entries, diagnostics


def _indirect_callsite_match_target(
    *,
    window_text: str,
    target_entry: dict[str, Any],
    class_prefixes: list[str],
) -> tuple[str, str] | None:
    tokens = _selector_dispatch_symbol_tokens(target_entry)
    full_tokens = [
        token
        for token in tokens
        if token and token != str(target_entry.get("short_name") or "")
    ]
    for token in sorted(full_tokens, key=len, reverse=True):
        if token and token in window_text:
            return token, "full-symbol"

    short_name = str(target_entry.get("short_name") or "").strip()
    if (
        not short_name
        or len(short_name) < 3
        or not _indirect_callsite_short_name_in_text(short_name, window_text)
    ):
        return None
    if bool(target_entry.get("_synthetic_target")):
        return short_name, "requested-symbol"
    if class_prefixes and any(
        prefix and prefix in window_text for prefix in class_prefixes
    ):
        return short_name, "class-scoped-short-symbol"
    return None


def _indirect_callsite_short_name_in_text(short_name: str, text: str) -> bool:
    token = str(short_name or "").strip()
    if not token:
        return False
    return bool(
        re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", str(text or "")
        )
    )


def _indirect_callsite_row_has_indirect_callee(row_text: str) -> bool:
    text = str(row_text or "").strip()
    lowered = text.lower()
    if lowered.startswith(("icall", "calli", "mcall", "blr ", "blx ")):
        return True
    match = re.search(r"\bcall\b", text)
    if not match:
        return False
    callee = text[match.end() :].lstrip()
    if callee.startswith("$") or callee.startswith("!"):
        return False
    return any(marker in callee for marker in ("(*", "[", "vptr"))


def _indirect_callsite_row_is_indirect(row: dict[str, Any], row_text: str) -> bool:
    opcode_name = str(row.get("opcode_name") or "").strip()
    if opcode_name == "m_icall":
        return True
    return _indirect_callsite_row_has_indirect_callee(row_text)


def _indirect_callsite_slot_evidence(
    window_text: str, row_text: str = ""
) -> dict[str, Any]:
    lowered = window_text.lower()
    has_vtable_marker = any(
        marker in lowered for marker in _INDIRECT_CALLSITE_VTABLE_MARKERS
    )
    row_slot_match = (
        _INDIRECT_CALLSITE_CALLEE_SLOT_RE.search(row_text)
        if has_vtable_marker
        else None
    )
    slot_match = row_slot_match or _INDIRECT_CALLSITE_SLOT_RE.search(window_text)
    vtable_match = _INDIRECT_CALLSITE_VTABLE_SYMBOL_RE.search(window_text)
    evidence: dict[str, Any] = {
        "dispatch_slot_observed": bool(slot_match),
        "exact_vtable_slot_observed": bool(has_vtable_marker and slot_match),
    }
    if slot_match:
        slot_offset = next((group for group in slot_match.groups() if group), "")
        evidence["slot_offset"] = slot_offset
        parsed_slot_offset = _int_from_hex_text(slot_offset)
        if parsed_slot_offset is not None:
            evidence["slot_offset_int"] = parsed_slot_offset
    if vtable_match:
        evidence["vtable_symbol"] = vtable_match.group(1)
    return evidence


def _indirect_callsite_diagnostic_rows(
    *,
    rows: list[dict[str, Any]],
    caller_function: str,
    caller_ea: str,
    max_rows: int = 64,
) -> list[dict[str, Any]]:
    """Return bounded diagnostic rows for concrete indirect microcode calls."""

    max_count = max(1, int(max_rows or 64))
    diagnostics: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        row_text = _microcode_row_text(row)
        if not _indirect_callsite_row_is_indirect(row, row_text):
            continue
        start = max(0, index - 5)
        end = min(len(rows), index + 8)
        window_rows = rows[start:end]
        window_text = "\n".join(_microcode_row_text(item) for item in window_rows)
        slot_evidence = _indirect_callsite_slot_evidence(window_text, row_text=row_text)
        diagnostics.append(
            {
                "dispatch_function": caller_function,
                "function_ea": caller_ea,
                "row_index": index,
                "site_ea": str(row.get("ea") or "").strip(),
                "opcode": row.get("opcode"),
                "opcode_name": str(row.get("opcode_name") or "").strip(),
                "text": _microcode_preview_text(row_text, 1200),
                "operands": [
                    _microcode_preview_text(str(operand or ""), 240)
                    for operand in list(row.get("operands") or [])
                ],
                "slot_evidence": slot_evidence,
                "window": _microcode_preview_text(window_text, 2400),
                "indirect_reason": (
                    "m_icall"
                    if str(row.get("opcode_name") or "").strip() == "m_icall"
                    else "text-indirect-callee"
                ),
            }
        )
        if len(diagnostics) >= max_count:
            break
    return diagnostics


def _indirect_callsite_class_context_observed(
    *,
    caller_function: str,
    window_text: str,
    class_prefixes: list[str],
    vtable_entry: dict[str, Any],
) -> bool:
    tokens = _class_context_tokens_for_vtable_entry(vtable_entry, class_prefixes)
    haystacks = [str(caller_function or ""), str(window_text or "")]
    for token in tokens:
        if any(token and token in haystack for haystack in haystacks):
            return True
    return False


def _indirect_callsite_target_matches_vtable_entry(
    target_entry: dict[str, Any], vtable_entry: dict[str, Any]
) -> bool:
    target_tokens = _selector_dispatch_symbol_tokens(target_entry)
    vtable_target_tokens = [
        str(vtable_entry.get("target_ea") or ""),
        str(vtable_entry.get("target_function") or ""),
        str(vtable_entry.get("target_demangled_name") or ""),
        str(vtable_entry.get("target_short_name") or ""),
    ]
    return any(
        token and other and (token == other or token in other or other in token)
        for token in target_tokens
        for other in vtable_target_tokens
    )


def _indirect_callsite_match_vtable_slot(
    *,
    slot_evidence: dict[str, Any],
    caller_function: str,
    window_text: str,
    target_entry: dict[str, Any],
    class_prefixes: list[str],
    vtable_entries: list[dict[str, Any]],
) -> dict[str, Any] | None:
    slot_offset = slot_evidence.get("slot_offset_int")
    if slot_offset is None:
        return None
    for vtable_entry in vtable_entries or []:
        offsets = {
            _int_from_hex_text(vtable_entry.get("vtable_entry_offset")),
            _int_from_hex_text(vtable_entry.get("address_point_adjusted_offset")),
        }
        offsets.discard(None)
        if int(slot_offset) not in offsets:
            continue
        if not _indirect_callsite_target_matches_vtable_entry(
            target_entry, vtable_entry
        ):
            continue
        if class_prefixes and not any(
            prefix
            and any(prefix in token for token in _vtable_symbol_tokens(vtable_entry))
            for prefix in class_prefixes
        ):
            continue
        if not _indirect_callsite_class_context_observed(
            caller_function=caller_function,
            window_text=window_text,
            class_prefixes=class_prefixes,
            vtable_entry=vtable_entry,
        ):
            continue
        return dict(vtable_entry)
    return None


def _indirect_callsite_facts_from_microcode_rows(
    *,
    rows: list[dict[str, Any]],
    dispatch_so: str,
    caller_function: str,
    caller_ea: str,
    function_symbols: list[dict[str, Any]],
    vtable_entries: list[dict[str, Any]] | None = None,
    target_functions: Any = "",
    target_method_names: Any = "",
    class_prefixes: Any = "",
    extractor_profile: str = "generic_indirect_callsite",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    target_entries, diagnostics = _indirect_callsite_target_entries(
        function_symbols=function_symbols,
        target_functions=target_functions,
        target_method_names=target_method_names,
        class_prefixes=class_prefixes,
    )
    if not target_entries:
        return [], diagnostics

    prefixes = [
        str(item).strip()
        for item in normalize_list_input(class_prefixes)
        if str(item).strip()
    ]
    profile = _indirect_callsite_profile(extractor_profile)
    facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for index, row in enumerate(rows):
        row_text = _microcode_row_text(row)
        if not _indirect_callsite_row_is_indirect(row, row_text):
            continue
        start = max(0, index - 5)
        end = min(len(rows), index + 8)
        window_rows = rows[start:end]
        window_text = "\n".join(_microcode_row_text(item) for item in window_rows)
        context_start = max(0, index - 24)
        context_rows = rows[context_start:end]
        context_window_text = "\n".join(
            _microcode_row_text(item) for item in context_rows
        )
        slot_evidence = _indirect_callsite_slot_evidence(window_text, row_text=row_text)
        for target in target_entries:
            match = _indirect_callsite_match_target(
                window_text=row_text,
                target_entry=target,
                class_prefixes=prefixes,
            )
            vtable_slot_match: dict[str, Any] | None = None
            if not match:
                vtable_slot_match = _indirect_callsite_match_vtable_slot(
                    slot_evidence=slot_evidence,
                    caller_function=caller_function,
                    window_text=context_window_text,
                    target_entry=target,
                    class_prefixes=prefixes,
                    vtable_entries=list(vtable_entries or []),
                )
                if vtable_slot_match:
                    match = (
                        str(
                            vtable_slot_match.get("target_function")
                            or vtable_slot_match.get("target_demangled_name")
                            or ""
                        ),
                        "static-vtable-slot",
                    )
            if not match:
                continue
            matched_symbol, match_kind = match
            target_name = str(
                target.get("name") or target.get("demangled_name") or matched_symbol
            )
            target_ea = str(target.get("ea") or "").strip()
            callsite_ea = str(row.get("ea") or "").strip()
            key = (callsite_ea or str(index), caller_function, target_name)
            if key in seen:
                continue
            seen.add(key)
            identity: dict[str, Any] = {
                "caller_ea": caller_ea,
                "callsite_ea": callsite_ea,
                "microcode_row": index,
            }
            if target_ea:
                identity["target_ea"] = target_ea
            if slot_evidence.get("slot_offset"):
                identity["slot_offset"] = slot_evidence["slot_offset"]
            if vtable_slot_match:
                for key_name in (
                    "vtable_ea",
                    "vtable_entry_offset",
                    "address_point_adjusted_offset",
                    "slot_index",
                    "itanium_slot_index",
                ):
                    if vtable_slot_match.get(key_name) not in ("", None):
                        identity[key_name] = vtable_slot_match[key_name]
            provenance = {
                "source": "microcode",
                "pattern": "microcode_indirect_callsite",
                "extractor_tool": "extract_indirect_callsite_microcode_facts",
                "extractor_profile": profile,
                "caller_function": caller_function,
                "caller_ea": caller_ea,
                "target_ea": target_ea,
                "matched_symbol": matched_symbol,
                "match_kind": match_kind,
                "microcode_row": index,
                "site_ea": callsite_ea,
                "callsite_ea": callsite_ea,
                "microcode_text": _microcode_preview_text(row_text, 1200),
                "microcode_window": _microcode_preview_text(window_text, 4000),
                "exact_callsite_observed": True,
                "exact_vtable_slot_observed": bool(
                    slot_evidence.get("exact_vtable_slot_observed") or vtable_slot_match
                ),
                "dispatch_slot_observed": bool(
                    slot_evidence.get("dispatch_slot_observed")
                ),
            }
            for key_name in ("slot_offset", "vtable_symbol"):
                if slot_evidence.get(key_name):
                    provenance[key_name] = slot_evidence[key_name]
            if vtable_slot_match:
                provenance.update(
                    {
                        "vtable_slot_resolved_from_static_vtable": True,
                        "vtable_symbol": str(
                            vtable_slot_match.get("vtable_symbol")
                            or vtable_slot_match.get("vtable_demangled_name")
                            or provenance.get("vtable_symbol")
                            or ""
                        ),
                        "vtable_class_name": str(
                            vtable_slot_match.get("class_name") or ""
                        ),
                        "vtable_entry_offset": str(
                            vtable_slot_match.get("vtable_entry_offset") or ""
                        ),
                        "address_point_adjusted_offset": str(
                            vtable_slot_match.get("address_point_adjusted_offset") or ""
                        ),
                        "vtable_slot_index": vtable_slot_match.get("slot_index"),
                        "itanium_slot_index": vtable_slot_match.get(
                            "itanium_slot_index"
                        ),
                    }
                )
            facts.append(
                {
                    "kind": "function_table_callback",
                    "source_kind": "microcode-indirect-callsite",
                    "edge_kind": "semantic_dispatch",
                    "edge_strength": "conditional_semantic",
                    "dispatch_so": dispatch_so,
                    "dispatch_function": caller_function,
                    "target_so": dispatch_so,
                    "target_function": target_name,
                    "table_name": "indirect-callsite",
                    "slot_name": callsite_ea or f"microcode-row:{index}",
                    "confidence": (
                        0.86 if provenance.get("exact_vtable_slot_observed") else 0.80
                    ),
                    "validity_conditions": [
                        {
                            "condition_kind": "indirect_callsite",
                            "value": callsite_ea or f"microcode-row:{index}",
                        },
                        {
                            "condition_kind": "target_symbol_match",
                            "value": matched_symbol,
                        },
                    ],
                    "identity": identity,
                    "provenance": provenance,
                }
            )
            if vtable_slot_match:
                facts[-1]["validity_conditions"].append(
                    {
                        "condition_kind": "vtable_symbol",
                        "value": str(
                            vtable_slot_match.get("vtable_symbol")
                            or vtable_slot_match.get("vtable_demangled_name")
                            or ""
                        ),
                    }
                )
                facts[-1]["validity_conditions"].append(
                    {
                        "condition_kind": "vtable_entry_offset",
                        "value": str(
                            vtable_slot_match.get("vtable_entry_offset") or ""
                        ),
                    }
                )
    return facts, diagnostics


def _microcode_debug_lines(
    cfunc: Any, max_lines: int = 4000
) -> tuple[list[str], list[dict[str, Any]]]:
    rows, diagnostics = _microcode_rows(cfunc, max_lines=max_lines)
    return [str(row.get("text") or "") for row in rows], diagnostics


def _microcode_rows(
    cfunc: Any, max_lines: int = 4000
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    diagnostics: list[dict[str, Any]] = []
    mba = None
    getter = getattr(cfunc, "get_mba", None)
    try:
        mba = getter() if callable(getter) else getattr(cfunc, "mba", None)
    except Exception as exc:
        diagnostics.append({"code": "microcode-mba-unavailable", "message": str(exc)})
        return [], diagnostics
    if mba is None:
        diagnostics.append(
            {"code": "microcode-mba-unavailable", "message": "cfunc has no mba"}
        )
        return [], diagnostics
    try:
        qty = int(getattr(mba, "qty", 0) or 0)
    except Exception:
        qty = 0
    rows: list[dict[str, Any]] = []
    for block_index in range(max(0, qty)):
        try:
            block = mba.get_mblock(block_index)
        except Exception as exc:
            diagnostics.append(
                {
                    "code": "microcode-block-unavailable",
                    "block": block_index,
                    "message": str(exc),
                }
            )
            continue
        insn = getattr(block, "head", None)
        guard = 0
        while insn is not None and guard < 10000 and len(rows) < max_lines:
            guard += 1
            rows.append(
                {
                    "block": block_index,
                    "index": len(rows),
                    "ea": _safe_hex_ea(getattr(insn, "ea", None)),
                    "opcode": getattr(insn, "opcode", None),
                    "opcode_name": _microcode_opcode_name(
                        getattr(insn, "opcode", None)
                    ),
                    "text": _microcode_insn_text(insn),
                    "operands": [
                        _microcode_operand_text(getattr(insn, "l", None)),
                        _microcode_operand_text(getattr(insn, "r", None)),
                        _microcode_operand_text(getattr(insn, "d", None)),
                    ],
                }
            )
            insn = getattr(insn, "next", None)
        if len(rows) >= max_lines:
            diagnostics.append(
                {"code": "microcode-lines-truncated", "max_lines": max_lines}
            )
            break
    return rows, diagnostics


def _current_input_file_basename() -> str:
    try:
        import idc

        return os.path.basename(str(idc.get_input_file_path()))
    except Exception:
        return ""


def _extract_selector_dispatch_microcode_facts_impl(
    *,
    dispatch_funcs: Any = "",
    registration_funcs: Any = "",
    max_functions: int = 16,
    expected_selectors: Any = "",
    selector_min: int | None = None,
    selector_max: int | None = None,
    handler_prefixes: Any = "",
    target_functions: Any = "",
    extractor_profile: str = "generic_selector_dispatch",
    infer_handler_family_from_registration: bool = True,
) -> dict[str, Any]:
    profile = _selector_dispatch_profile(extractor_profile)
    raw_result: dict[str, Any] = {
        "tool": "extract_selector_dispatch_microcode_facts",
        "extractor_profile": profile,
        "source": "ida_hexrays_microcode",
        "raw_facts": [],
        "functions": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays
    except Exception as exc:
        raw_result["diagnostics"].append(
            {
                "code": "microcode-unavailable",
                "message": str(exc),
            }
        )
        raw_result["partial"] = True
        return raw_result

    dispatch_targets = normalize_list_input(dispatch_funcs)
    registration_targets = normalize_list_input(registration_funcs)
    targets = list(dict.fromkeys(registration_targets + dispatch_targets))
    if not targets:
        raw_result["diagnostics"].append(
            {
                "code": "empty-scope",
                "message": "dispatch_funcs or registration_funcs must select at least one function",
            }
        )
        raw_result["partial"] = True
        return raw_result

    max_count = max(1, int(max_functions or 16))
    selector_allow = _hdf_int_set(expected_selectors)
    min_selector = int(selector_min) if selector_min is not None else None
    max_selector = int(selector_max) if selector_max is not None else None
    handler_filter = [
        str(item)
        for item in normalize_list_input(handler_prefixes)
        if str(item).strip()
    ]
    target_filter = [
        str(item).strip()
        for item in normalize_list_input(target_functions)
        if str(item).strip()
    ]
    function_symbols = _list_ida_function_symbols()
    current_so = _current_input_file_basename()
    dispatcher_function = str(dispatch_targets[0]) if dispatch_targets else ""
    if len(targets) > max_count:
        raw_result["diagnostics"].append(
            {
                "code": "target-scope-truncated",
                "requested_targets": len(targets),
                "max_functions": max_count,
            }
        )
        raw_result["partial"] = True

    for target in targets[:max_count]:
        entry: dict[str, Any] = {
            "target": target,
            "function_ea": "",
            "function_name": "",
            "microcode_available": False,
            "microcode_line_count": 0,
            "diagnostics": [],
        }
        try:
            function_ea, function_name = _resolve_function(str(target))
            entry["function_ea"] = hex(function_ea)
            entry["function_name"] = function_name
        except Exception as exc:
            entry["diagnostics"].append(
                {"code": "function-resolution-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            entry["diagnostics"].append(
                {"code": "decompile-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue
        if not cfunc:
            entry["diagnostics"].append(
                {"code": "decompile-failed", "message": "decompile returned None"}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue

        rows, diagnostics = _microcode_rows(cfunc)
        for row in rows:
            row["function_ea"] = hex(function_ea)
        entry["microcode_available"] = bool(rows)
        entry["microcode_line_count"] = len(rows)
        entry["microcode_samples"] = [
            _microcode_preview_text(_microcode_row_text(row)) for row in rows[:8]
        ]
        entry["diagnostics"].extend(diagnostics)
        if diagnostics:
            raw_result["partial"] = True

        effective_handler_filter = list(handler_filter)
        inferred_handler_hints: list[str] = []
        if not effective_handler_filter and infer_handler_family_from_registration:
            inferred_handler_hints = _selector_dispatch_infer_handler_family_hints(
                function_name,
                function_symbols,
            )
            effective_handler_filter.extend(inferred_handler_hints)
        if effective_handler_filter:
            entry["handler_prefixes_used"] = effective_handler_filter
            entry["handler_prefix_source"] = (
                "configured" if handler_filter else "inferred-registration-family"
            )
        if target_filter:
            entry["target_functions_used"] = target_filter
        elif not selector_allow and min_selector is None and max_selector is None:
            entry["diagnostics"].append(
                {
                    "code": "broad-selector-dispatch-scope",
                    "message": (
                        "No selector filter or handler family filter was provided or inferred; "
                        "results require registration markers and remain bounded by max_functions."
                    ),
                }
            )
            raw_result["partial"] = True

        is_dispatch_target = any(
            str(item) == str(target) or str(item) == function_name
            for item in dispatch_targets
        )
        if selector_allow and is_dispatch_target:
            endpoint_count = 0
            for selector in sorted(selector_allow):
                raw_result["raw_facts"].append(
                    {
                        "kind": "selector_dispatch_dispatcher",
                        "dispatch_so": current_so,
                        "dispatch_function": function_name,
                        "selector": selector,
                        "selector_source": "configured-selector",
                        "confidence": 0.82,
                        "provenance": {
                            "source": "microcode",
                            "pattern": "microcode_selector_dispatch_dispatcher_endpoint",
                            "extractor_profile": profile,
                            "dispatch_function": function_name,
                            "function_ea": hex(function_ea),
                            "selector_observed_in_dispatch": False,
                            "dispatch_function_resolved": True,
                        },
                    }
                )
                endpoint_count += 1
            entry["raw_dispatch_endpoint_count"] = endpoint_count

        diagnostic_count_before = len(entry["diagnostics"])
        facts = _selector_dispatch_facts_from_microcode_rows(
            rows=rows,
            dispatch_so=current_so,
            dispatch_function=dispatcher_function,
            dispatch_functions=[
                str(item) for item in dispatch_targets if str(item).strip()
            ],
            registration_function=function_name,
            function_symbols=function_symbols,
            expected_selectors=selector_allow,
            selector_min=min_selector,
            selector_max=max_selector,
            handler_prefixes=effective_handler_filter,
            target_functions=target_filter,
            extractor_profile=profile,
            emit_registration_partial=not is_dispatch_target,
            diagnostics_out=entry["diagnostics"],
        )
        if len(entry["diagnostics"]) > diagnostic_count_before:
            raw_result["partial"] = True
        raw_result["raw_facts"].extend(facts)
        entry["raw_fact_count"] = len(facts)
        raw_result["functions"].append(entry)
    return raw_result


def _extract_indirect_callsite_microcode_facts_impl(
    *,
    caller_funcs: Any = "",
    target_functions: Any = "",
    target_method_names: Any = "",
    class_prefixes: Any = "",
    max_functions: int = 16,
    extractor_profile: str = "generic_indirect_callsite",
) -> dict[str, Any]:
    profile = _indirect_callsite_profile(extractor_profile)
    raw_result: dict[str, Any] = {
        "tool": "extract_indirect_callsite_microcode_facts",
        "extractor_profile": profile,
        "source": "ida_hexrays_microcode",
        "raw_facts": [],
        "functions": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays
    except Exception as exc:
        raw_result["diagnostics"].append(
            {
                "code": "microcode-unavailable",
                "message": str(exc),
            }
        )
        raw_result["partial"] = True
        return raw_result

    callers = [
        str(item).strip()
        for item in normalize_list_input(caller_funcs)
        if str(item).strip()
    ]
    if not callers:
        raw_result["diagnostics"].append(
            {
                "code": "empty-scope",
                "message": "caller_funcs must select at least one function",
            }
        )
        raw_result["partial"] = True
        return raw_result

    function_symbols = _list_ida_function_symbols()
    targets, target_diagnostics = _indirect_callsite_target_entries(
        function_symbols=function_symbols,
        target_functions=target_functions,
        target_method_names=target_method_names,
        class_prefixes=class_prefixes,
    )
    raw_result["diagnostics"].extend(target_diagnostics)
    if target_diagnostics:
        raw_result["partial"] = True
    if not targets:
        return raw_result

    max_count = max(1, int(max_functions or 16))
    if len(callers) > max_count:
        raw_result["diagnostics"].append(
            {
                "code": "target-scope-truncated",
                "requested_targets": len(callers),
                "max_functions": max_count,
            }
        )
        raw_result["partial"] = True

    vtable_entries = _list_ida_vtable_slot_entries(function_symbols)
    raw_result["vtable_slot_entry_count"] = len(vtable_entries)
    current_so = _current_input_file_basename()
    for caller in callers[:max_count]:
        entry: dict[str, Any] = {
            "target": caller,
            "function_ea": "",
            "function_name": "",
            "microcode_available": False,
            "microcode_line_count": 0,
            "diagnostics": [],
        }
        try:
            function_ea, function_name = _resolve_function(str(caller))
            entry["function_ea"] = hex(function_ea)
            entry["function_name"] = function_name
        except Exception as exc:
            entry["diagnostics"].append(
                {"code": "function-resolution-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            entry["diagnostics"].append(
                {"code": "decompile-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue
        if not cfunc:
            entry["diagnostics"].append(
                {"code": "decompile-failed", "message": "decompile returned None"}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue

        rows, diagnostics = _microcode_rows(cfunc)
        for row in rows:
            row["function_ea"] = hex(function_ea)
        entry["microcode_available"] = bool(rows)
        entry["microcode_line_count"] = len(rows)
        entry["microcode_samples"] = [
            _microcode_preview_text(_microcode_row_text(row)) for row in rows[:8]
        ]
        entry["diagnostics"].extend(diagnostics)
        if diagnostics:
            raw_result["partial"] = True

        facts, fact_diagnostics = _indirect_callsite_facts_from_microcode_rows(
            rows=rows,
            dispatch_so=current_so,
            caller_function=function_name,
            caller_ea=hex(function_ea),
            function_symbols=function_symbols,
            vtable_entries=vtable_entries,
            target_functions=target_functions,
            target_method_names=target_method_names,
            class_prefixes=class_prefixes,
            extractor_profile=profile,
        )
        if fact_diagnostics:
            entry["diagnostics"].extend(fact_diagnostics)
            raw_result["partial"] = True
        raw_result["raw_facts"].extend(facts)
        entry["raw_fact_count"] = len(facts)
        raw_result["functions"].append(entry)
    return raw_result


def _list_indirect_callsite_microcode_rows_impl(
    *,
    caller_funcs: Any = "",
    max_functions: int = 16,
    max_rows_per_function: int = 64,
) -> dict[str, Any]:
    raw_result: dict[str, Any] = {
        "tool": "list_indirect_callsite_microcode_rows",
        "source": "ida_hexrays_microcode",
        "rows": [],
        "functions": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays
    except Exception as exc:
        raw_result["diagnostics"].append(
            {
                "code": "microcode-unavailable",
                "message": str(exc),
            }
        )
        raw_result["partial"] = True
        return raw_result

    callers = [
        str(item).strip()
        for item in normalize_list_input(caller_funcs)
        if str(item).strip()
    ]
    if not callers:
        raw_result["diagnostics"].append(
            {
                "code": "empty-scope",
                "message": "caller_funcs must select at least one function",
            }
        )
        raw_result["partial"] = True
        return raw_result

    max_count = max(1, int(max_functions or 16))
    if len(callers) > max_count:
        raw_result["diagnostics"].append(
            {
                "code": "target-scope-truncated",
                "requested_targets": len(callers),
                "max_functions": max_count,
            }
        )
        raw_result["partial"] = True

    row_limit = max(1, int(max_rows_per_function or 64))
    for caller in callers[:max_count]:
        entry: dict[str, Any] = {
            "target": caller,
            "function_ea": "",
            "function_name": "",
            "microcode_available": False,
            "microcode_line_count": 0,
            "indirect_row_count": 0,
            "diagnostics": [],
        }
        try:
            function_ea, function_name = _resolve_function(str(caller))
            entry["function_ea"] = hex(function_ea)
            entry["function_name"] = function_name
        except Exception as exc:
            entry["diagnostics"].append(
                {"code": "function-resolution-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            entry["diagnostics"].append(
                {"code": "decompile-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue
        if not cfunc:
            entry["diagnostics"].append(
                {"code": "decompile-failed", "message": "decompile returned None"}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue

        rows, diagnostics = _microcode_rows(cfunc)
        for row in rows:
            row["function_ea"] = hex(function_ea)
        entry["microcode_available"] = bool(rows)
        entry["microcode_line_count"] = len(rows)
        entry["diagnostics"].extend(diagnostics)
        if diagnostics:
            raw_result["partial"] = True
        indirect_rows = _indirect_callsite_diagnostic_rows(
            rows=rows,
            caller_function=function_name,
            caller_ea=hex(function_ea),
            max_rows=row_limit,
        )
        entry["indirect_row_count"] = len(indirect_rows)
        if len(indirect_rows) >= row_limit:
            entry["diagnostics"].append(
                {
                    "code": "indirect-callsite-rows-truncated",
                    "max_rows_per_function": row_limit,
                }
            )
            raw_result["partial"] = True
        raw_result["rows"].extend(indirect_rows)
        raw_result["functions"].append(entry)
    return raw_result


@register_tool
def extract_hdf_ril_dispatch_microcode_facts(
    dispatch_funcs: Annotated[list[str] | str, "Dispatcher functions to inspect"] = "",
    registration_funcs: Annotated[
        list[str] | str, "Registration/map-initializer functions to inspect"
    ] = "",
    max_functions: Annotated[int, "Maximum functions to inspect"] = 16,
    expected_selectors: Annotated[
        list[int] | str, "Optional exact selector allow-list"
    ] = "",
    selector_min: Annotated[int | None, "Optional minimum selector value"] = None,
    selector_max: Annotated[int | None, "Optional maximum selector value"] = None,
    handler_prefixes: Annotated[
        list[str] | str, "Optional handler symbol prefixes/substrings"
    ] = "",
) -> dict:
    """Best-effort HDF/RIL dispatch raw-fact collector over Hex-Rays microcode.

    This tool intentionally returns backend-owned raw facts, not semantic
    overlays or verdicts.  The first version exposes microcode availability and
    debug lines while keeping the raw fact schema stable for the backend
    normalizer.  Unsupported patterns return diagnostics and an empty fact set
    instead of pretending the edge is unreachable.
    """

    raw_result: dict[str, Any] = {
        "tool": "extract_hdf_ril_dispatch_microcode_facts",
        "raw_facts": [],
        "functions": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays

        dispatch_targets = normalize_list_input(dispatch_funcs)
        registration_targets = normalize_list_input(registration_funcs)
        targets = list(dict.fromkeys(dispatch_targets + registration_targets))
        max_count = max(1, int(max_functions or 16))
        selector_allow = _hdf_int_set(expected_selectors)
        min_selector = int(selector_min) if selector_min is not None else None
        max_selector = int(selector_max) if selector_max is not None else None
        handler_filter = [
            str(item)
            for item in normalize_list_input(handler_prefixes)
            if str(item).strip()
        ]
        function_symbols = _list_ida_function_symbols()
        current_so = _current_input_file_basename()
        for target in targets[:max_count]:
            function_ea, function_name = _resolve_function(str(target))
            entry: dict[str, Any] = {
                "target": target,
                "function_ea": hex(function_ea),
                "function_name": function_name,
                "microcode_available": False,
                "microcode_line_count": 0,
                "diagnostics": [],
            }
            try:
                cfunc = ida_hexrays.decompile(function_ea)
            except Exception as exc:
                entry["diagnostics"].append(
                    {"code": "decompile-failed", "message": str(exc)}
                )
                raw_result["partial"] = True
                raw_result["functions"].append(entry)
                continue
            if not cfunc:
                entry["diagnostics"].append(
                    {"code": "decompile-failed", "message": "decompile returned None"}
                )
                raw_result["partial"] = True
                raw_result["functions"].append(entry)
                continue
            rows, diagnostics = _microcode_rows(cfunc)
            for row in rows:
                row["function_ea"] = hex(function_ea)
            entry["microcode_available"] = bool(rows)
            entry["microcode_line_count"] = len(rows)
            entry["microcode_samples"] = [
                _microcode_preview_text(_microcode_row_text(row)) for row in rows[:8]
            ]
            entry["diagnostics"].extend(diagnostics)
            if diagnostics:
                raw_result["partial"] = True
            if (
                str(target) in registration_targets
                or function_name in registration_targets
            ):
                facts = _hdf_registration_facts_from_microcode_rows(
                    rows=rows,
                    from_so=current_so,
                    dispatcher_function=(
                        str(dispatch_targets[0]) if dispatch_targets else ""
                    ),
                    registration_function=function_name,
                    function_symbols=function_symbols,
                    expected_selectors=selector_allow,
                    selector_min=min_selector,
                    selector_max=max_selector,
                    handler_prefixes=handler_filter,
                )
                raw_result["raw_facts"].extend(facts)
                entry["raw_fact_count"] = len(facts)
            raw_result["functions"].append(entry)
        return raw_result
    except Exception as exc:
        raw_result["diagnostics"].append({"code": "tool-error", "message": str(exc)})
        raw_result["partial"] = True
        return raw_result


@register_tool
def extract_selector_dispatch_microcode_facts(
    dispatch_funcs: Annotated[list[str] | str, "Dispatcher functions to inspect"] = "",
    registration_funcs: Annotated[
        list[str] | str, "Registration/map-initializer functions to inspect"
    ] = "",
    max_functions: Annotated[int, "Maximum functions to inspect"] = 16,
    expected_selectors: Annotated[
        list[int] | str, "Optional exact selector allow-list"
    ] = "",
    selector_min: Annotated[int | None, "Optional minimum selector value"] = None,
    selector_max: Annotated[int | None, "Optional maximum selector value"] = None,
    handler_prefixes: Annotated[
        list[str] | str, "Optional handler symbol prefixes/substrings"
    ] = "",
    target_functions: Annotated[
        list[str] | str,
        "Optional target function allow-list by raw, demangled, or short name",
    ] = "",
    extractor_profile: Annotated[
        str, "Configured microcode extractor profile"
    ] = "generic_selector_dispatch",
    infer_handler_family_from_registration: Annotated[
        bool,
        "Infer C++ class/family handler prefix from registration function when handler_prefixes is empty",
    ] = True,
) -> dict:
    """Read-only microcode selector-dispatch raw fact extractor.

    Contract:
    - Input is a bounded dispatch/registration scope for the currently opened
      binary.
    - Output raw facts are canonical ``selector_dispatch_entry`` records.
    - Diagnostics are explicit; unsupported/partial extraction returns an empty
      fact set instead of a reachability conclusion.
    """

    if (
        str(extractor_profile or "generic_selector_dispatch").strip()
        not in _SELECTOR_DISPATCH_SUPPORTED_PROFILES
    ):
        return {
            "tool": "extract_selector_dispatch_microcode_facts",
            "raw_facts": [],
            "functions": [],
            "diagnostics": [
                {
                    "code": "unsupported-extractor-profile",
                    "message": f"unsupported selector dispatch microcode extractor profile: {extractor_profile}",
                }
            ],
            "partial": True,
        }
    return _extract_selector_dispatch_microcode_facts_impl(
        dispatch_funcs=dispatch_funcs,
        registration_funcs=registration_funcs,
        max_functions=max_functions,
        expected_selectors=expected_selectors,
        selector_min=selector_min,
        selector_max=selector_max,
        handler_prefixes=handler_prefixes,
        target_functions=target_functions,
        extractor_profile=str(extractor_profile or "generic_selector_dispatch"),
        infer_handler_family_from_registration=bool(
            infer_handler_family_from_registration
        ),
    )


@register_tool
def extract_indirect_callsite_microcode_facts(
    caller_funcs: Annotated[
        list[str] | str, "Caller functions to inspect for indirect callsites"
    ] = "",
    target_functions: Annotated[
        list[str] | str,
        "Optional exact target function allow-list by raw name, demangled name, or EA",
    ] = "",
    target_method_names: Annotated[
        list[str] | str, "Optional method names, scoped by class_prefixes"
    ] = "",
    class_prefixes: Annotated[
        list[str] | str,
        "Optional C++ class/symbol prefixes for short method-name matching",
    ] = "",
    max_functions: Annotated[int, "Maximum caller functions to inspect"] = 16,
    extractor_profile: Annotated[
        str, "Configured microcode extractor profile"
    ] = "generic_indirect_callsite",
) -> dict:
    """Read-only microcode indirect-callsite raw fact extractor.

    Contract:
    - Input is a bounded caller scope for the currently opened binary.
    - Target extraction is allow-list based.  Broad indirect-call enumeration
      returns diagnostics and no facts.
    - Output raw facts are canonical ``function_table_callback`` records that
      can be consumed by the generic function-table/callback overlay producer.
    - The tool records whether the callsite, dispatch slot, and concrete vtable
      slot were actually observed; it does not infer those fields from prose.
    """

    if (
        str(extractor_profile or "generic_indirect_callsite").strip()
        not in _INDIRECT_CALLSITE_SUPPORTED_PROFILES
    ):
        return {
            "tool": "extract_indirect_callsite_microcode_facts",
            "raw_facts": [],
            "functions": [],
            "diagnostics": [
                {
                    "code": "unsupported-extractor-profile",
                    "message": f"unsupported indirect callsite microcode extractor profile: {extractor_profile}",
                }
            ],
            "partial": True,
        }
    return _extract_indirect_callsite_microcode_facts_impl(
        caller_funcs=caller_funcs,
        target_functions=target_functions,
        target_method_names=target_method_names,
        class_prefixes=class_prefixes,
        max_functions=max_functions,
        extractor_profile=str(extractor_profile or "generic_indirect_callsite"),
    )


@register_tool
def list_indirect_callsite_microcode_rows(
    caller_funcs: Annotated[
        list[str] | str,
        "Caller functions to inspect for concrete indirect microcode rows",
    ] = "",
    max_functions: Annotated[int, "Maximum caller functions to inspect"] = 16,
    max_rows_per_function: Annotated[
        int, "Maximum indirect rows to return per function"
    ] = 64,
) -> dict:
    """Read-only diagnostic view of bounded indirect-callsite microcode rows.

    This tool is intentionally not a semantic-edge producer. It supports
    ground-truth and extractor development by showing whether a proof path
    function contains a real ``m_icall``/indirect callee row before a target
    resolver is asked to prove a concrete edge.
    """

    return _list_indirect_callsite_microcode_rows_impl(
        caller_funcs=caller_funcs,
        max_functions=max_functions,
        max_rows_per_function=max_rows_per_function,
    )


@register_tool
def list_vtable_slot_entries(
    class_prefixes: Annotated[
        list[str] | str, "Optional concrete class/vtable symbol prefixes or substrings"
    ] = "",
    target_functions: Annotated[
        list[str] | str,
        "Optional exact target function allow-list by raw name, demangled name, or EA",
    ] = "",
    slot_offsets: Annotated[
        list[str] | str, "Optional vtable/address-point slot offsets such as 0x40 or 64"
    ] = "",
    max_entries_per_vtable: Annotated[int, "Maximum slots to inspect per vtable"] = 128,
    max_entries: Annotated[int, "Maximum matching vtable entries to return"] = 5000,
) -> dict:
    """Read-only diagnostic view of concrete C++ vtable slot entries.

    The tool only reads IDA names and data pointers in the currently opened
    binary. It does not produce callgraph edges by itself; backend producers can
    join these target-side entries with bounded caller-side vtable callsite
    evidence.
    """

    prefixes = [
        str(item).strip()
        for item in normalize_list_input(class_prefixes)
        if str(item).strip()
    ]
    targets = [
        str(item).strip()
        for item in normalize_list_input(target_functions)
        if str(item).strip()
    ]
    offsets = {
        parsed
        for parsed in (
            _int_from_hex_text(item) for item in normalize_list_input(slot_offsets)
        )
        if parsed is not None
    }
    result: dict[str, Any] = {
        "tool": "list_vtable_slot_entries",
        "source": "ida_names_vtable_slots",
        "entries": [],
        "diagnostics": [],
        "partial": False,
    }
    function_symbols = _list_ida_function_symbols()
    all_entries = _list_ida_vtable_slot_entries(
        function_symbols,
        max_entries_per_vtable=max(1, int(max_entries_per_vtable or 128)),
    )
    limit = max(1, int(max_entries or 5000))
    for entry in all_entries:
        if not _vtable_entry_filter_match(
            dict(entry),
            class_prefixes=prefixes,
            target_functions=targets,
            slot_offsets=offsets,
        ):
            continue
        result["entries"].append(dict(entry))
        if len(result["entries"]) >= limit:
            result["partial"] = True
            result["diagnostics"].append(
                {
                    "code": "vtable-slot-entries-truncated",
                    "max_entries": limit,
                }
            )
            break
    result["entry_count"] = len(result["entries"])
    result["total_entry_count"] = len(all_entries)
    result["function_symbol_count"] = len(function_symbols)
    return result


@register_tool
def extract_vtable_callsite_decompile_facts(
    caller_funcs: Annotated[
        list[str] | str, "Caller functions to inspect for C++ vtable callsites"
    ] = "",
    receiver_type_prefixes: Annotated[
        list[str] | str, "Optional receiver static type prefixes/substrings"
    ] = "",
    slot_offsets: Annotated[
        list[str] | str, "Optional vtable/address-point slot offsets such as 0x40 or 64"
    ] = "",
    max_functions: Annotated[int, "Maximum caller functions to inspect"] = 16,
    max_callsites_per_function: Annotated[
        int, "Maximum callsites to return per function"
    ] = 64,
) -> dict:
    """Read-only caller-side C++ vtable callsite evidence from decompiled code.

    Output records are bounded ``vtable_callsite`` observations. They are not
    semantic edges until a backend producer joins them with concrete target-side
    vtable slot entries.
    """

    raw_result: dict[str, Any] = {
        "tool": "extract_vtable_callsite_decompile_facts",
        "source": "ida_hexrays_decompile",
        "callsites": [],
        "functions": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays
    except Exception as exc:
        raw_result["diagnostics"].append(
            {"code": "decompile-unavailable", "message": str(exc)}
        )
        raw_result["partial"] = True
        return raw_result

    callers = [
        str(item).strip()
        for item in normalize_list_input(caller_funcs)
        if str(item).strip()
    ]
    if not callers:
        raw_result["diagnostics"].append(
            {
                "code": "empty-scope",
                "message": "caller_funcs must select at least one function",
            }
        )
        raw_result["partial"] = True
        return raw_result

    receiver_prefixes = [
        str(item).strip()
        for item in normalize_list_input(receiver_type_prefixes)
        if str(item).strip()
    ]
    offsets = {
        parsed
        for parsed in (
            _int_from_hex_text(item) for item in normalize_list_input(slot_offsets)
        )
        if parsed is not None
    }
    max_count = max(1, int(max_functions or 16))
    if len(callers) > max_count:
        raw_result["diagnostics"].append(
            {
                "code": "target-scope-truncated",
                "requested_targets": len(callers),
                "max_functions": max_count,
            }
        )
        raw_result["partial"] = True

    current_so = _current_input_file_basename()
    for caller in callers[:max_count]:
        entry: dict[str, Any] = {
            "target": caller,
            "function_ea": "",
            "function_name": "",
            "decompile_available": False,
            "callsite_count": 0,
            "diagnostics": [],
        }
        try:
            function_ea, function_name = _resolve_function(str(caller))
            entry["function_ea"] = hex(function_ea)
            entry["function_name"] = function_name
        except Exception as exc:
            entry["diagnostics"].append(
                {"code": "function-resolution-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            entry["diagnostics"].append(
                {"code": "decompile-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue
        if not cfunc:
            entry["diagnostics"].append(
                {"code": "decompile-failed", "message": "decompile returned None"}
            )
            raw_result["partial"] = True
            raw_result["functions"].append(entry)
            continue

        entry["decompile_available"] = True
        callsites = _vtable_callsites_from_decompiled_code(
            code=str(cfunc),
            dispatch_so=current_so,
            caller_function=function_name,
            caller_ea=hex(function_ea),
            receiver_type_prefixes=receiver_prefixes,
            slot_offsets=offsets,
            max_callsites=max_callsites_per_function,
        )
        entry["callsite_count"] = len(callsites)
        if len(callsites) >= max(1, int(max_callsites_per_function or 64)):
            entry["diagnostics"].append(
                {
                    "code": "vtable-callsites-truncated",
                    "max_callsites_per_function": max(
                        1, int(max_callsites_per_function or 64)
                    ),
                }
            )
            raw_result["partial"] = True
        raw_result["callsites"].extend(callsites)
        raw_result["functions"].append(entry)
    raw_result["callsite_count"] = len(raw_result["callsites"])
    return raw_result


@register_tool
def extract_accesses(
    func: Annotated[
        str,
        "Target function address or name. The tool resolves it to function_ea and decompiles one function only.",
    ],
    filters: (
        Annotated[
            dict[str, Any],
            "Optional generic filters: symbols, include_globals, include_members, include_containers. Empty means return all generic access candidates.",
        ]
        | None
    ) = None,
) -> dict:
    """Extract generic global/member/container access facts.

    This is a structured fact extractor, not a vulnerability detector. It does
    not prove UAF, OOB, race, ownership, or lifetime safety by itself.

    Scope: best-effort intraprocedural extraction from Hex-Rays pseudocode,
    with site_ea recovered from nearby disassembly when possible.

    Output semantics: accesses[] contains expressions, bases, access_kind,
    access mode, line text, source refs, confidence, partial, and
    unavailable_reason. partial=true means the fact is still usable as a weak
    seed signal, but should not be treated as definitive proof.

    Limitations: no complete alias analysis, no cross-function lifetime proof,
    no lock correctness reasoning, and no profile-specific scoring. Callers
    must combine these facts with profile-specific seed/work-unit/evidence
    logic.
    """
    raw_result: dict[str, Any] = {
        "tool": "extract_accesses",
        "function_ea": None,
        "function_name": "",
        "accesses": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays

        filters = filters or {}
        function_ea, function_name = _resolve_function(func)
        raw_result["function_ea"] = hex(function_ea)
        raw_result["function_name"] = function_name
        raw_result["raw_name"] = function_name

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            raw_result["diagnostics"].append(
                {"code": "decompile-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            return normalize_extract_accesses_result(raw_result)

        if not cfunc:
            raw_result["diagnostics"].append(
                {"code": "decompile-failed", "message": "Decompilation failed"}
            )
            raw_result["partial"] = True
            return normalize_extract_accesses_result(raw_result)

        accesses = _with_access_site_eas(
            function_ea, _extract_access_facts_from_code(function_ea, str(cfunc))
        )
        raw_result["accesses"] = _filter_access_facts(accesses, filters)
        raw_result["partial"] = any(
            item.get("partial") for item in raw_result["accesses"]
        )
        return normalize_extract_accesses_result(raw_result)
    except Exception as exc:
        raw_result["diagnostics"].append({"code": "tool-error", "message": str(exc)})
        raw_result["partial"] = True
        return normalize_extract_accesses_result(raw_result)


@register_tool
def extract_lock_regions(
    func: Annotated[
        str,
        "Target function address or name. The tool resolves it to function_ea and decompiles one function only.",
    ],
    lock_names: Annotated[
        str | list[str],
        "Optional lock-name filter. Empty means return all suspected lock regions.",
    ] = "",
    lock_api_patterns: Annotated[
        str | list[str],
        "Optional regex filters for lock APIs/classes, e.g. unique_lock, lock_guard, pthread_mutex_lock. Empty means use built-in generic patterns.",
    ] = "",
) -> dict:
    """Extract generic lock/synchronization regions and covered accesses.

    This is a structured fact extractor, not a concurrency or race verdict.

    Scope: best-effort intraprocedural lock-region recovery from Hex-Rays
    pseudocode. It recognizes common RAII locks and explicit lock/unlock
    pairs, then attaches access facts whose pseudocode line range falls inside
    the inferred region.

    Output semantics: regions[] contains lock_name, lock_kind, line range,
    unlock_kind, covered_accesses, confidence, partial, and diagnostics.
    partial=true usually means the region boundary or exact site EA is only
    approximate.

    Limitations: no happens-before proof, no inter-thread ordering proof, no
    destructor-scope certainty for arbitrary C++ RAII patterns, and no
    profile-specific lock-coverage conclusion.
    """
    raw_result: dict[str, Any] = {
        "tool": "extract_lock_regions",
        "function_ea": None,
        "function_name": "",
        "regions": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays

        function_ea, function_name = _resolve_function(func)
        raw_result["function_ea"] = hex(function_ea)
        raw_result["function_name"] = function_name
        raw_result["raw_name"] = function_name

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            raw_result["diagnostics"].append(
                {"code": "decompile-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            return normalize_extract_lock_regions_result(raw_result)

        if not cfunc:
            raw_result["diagnostics"].append(
                {"code": "decompile-failed", "message": "Decompilation failed"}
            )
            raw_result["partial"] = True
            return normalize_extract_lock_regions_result(raw_result)

        code = str(cfunc)
        accesses = _with_access_site_eas(
            function_ea, _extract_access_facts_from_code(function_ea, code)
        )
        raw_result["regions"] = _extract_lock_regions_from_code(
            function_ea,
            code,
            lock_names=[str(item) for item in normalize_list_input(lock_names)],
            lock_api_patterns=[
                str(item) for item in normalize_list_input(lock_api_patterns)
            ],
            accesses=accesses,
        )
        raw_result["partial"] = any(
            item.get("partial") for item in raw_result["regions"]
        )
        return normalize_extract_lock_regions_result(raw_result)
    except Exception as exc:
        raw_result["diagnostics"].append({"code": "tool-error", "message": str(exc)})
        raw_result["partial"] = True
        return normalize_extract_lock_regions_result(raw_result)


@register_tool
def extract_carrier_facts(
    func: Annotated[
        str,
        "Target function address or name. The tool resolves it to function_ea and decompiles one function only.",
    ],
    filters: (
        Annotated[
            dict[str, Any],
            "Optional generic filters forwarded to access/call extraction, such as symbols, callee_filter, and max_calls.",
        ]
        | None
    ) = None,
) -> dict:
    """Aggregate generic lifecycle carrier facts from access/invalidation/lock facts.

    This is a structured fact extractor. It groups raw facts around a carrier
    key such as a global registry, member container, handle map,
    queue/cache/pool, or ref wrapper. It does not decide whether a carrier is
    stale, freed, racy, exploitable, or safe.

    Scope: best-effort intraprocedural aggregation. It reuses generic access,
    assignment, invalidation-like call, and lock-region facts.

    Output semantics: carriers[] contains key, kind, accesses, invalidations,
    aliases, locks, site_eas, confidence, partial, and unavailable_reason.
    partial=true means the carrier grouping is heuristic and should be used as
    a candidate seed only.

    Limitations: no complete alias graph, no destructor/teardown completeness
    proof, no cross-function registration/deregistration matching, and no
    vulnerability verdict.
    """
    raw_result: dict[str, Any] = {
        "tool": "extract_carrier_facts",
        "function_ea": None,
        "function_name": "",
        "carriers": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays

        filters = filters or {}
        function_ea, function_name = _resolve_function(func)
        raw_result["function_ea"] = hex(function_ea)
        raw_result["function_name"] = function_name
        raw_result["raw_name"] = function_name

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            raw_result["diagnostics"].append(
                {"code": "decompile-failed", "message": str(exc)}
            )
            raw_result["partial"] = True
            return normalize_extract_carrier_facts_result(raw_result)

        if not cfunc:
            raw_result["diagnostics"].append(
                {"code": "decompile-failed", "message": "Decompilation failed"}
            )
            raw_result["partial"] = True
            return normalize_extract_carrier_facts_result(raw_result)

        code = str(cfunc)
        callsites = _list_callsites_from_decompiled_code(
            function_ea=function_ea,
            function_name=function_name,
            code=code,
            callee_filter=str(filters.get("callee_filter", "*")),
            include_args=True,
            max_calls=int(filters.get("max_calls", 0) or 0),
        )
        accesses = _filter_access_facts(
            _with_access_site_eas(
                function_ea, _extract_access_facts_from_code(function_ea, code)
            ),
            filters,
        )
        assignments = _extract_assignment_facts_from_code(function_ea, code)
        invalidations = _extract_invalidation_facts_from_calls(
            callsites
        ) + _extract_invalidation_facts_from_code(function_ea, code)
        locks = _extract_lock_regions_from_code(function_ea, code, accesses=accesses)
        raw_result["carriers"] = _aggregate_carrier_facts(
            function_ea=function_ea,
            accesses=accesses,
            invalidations=invalidations,
            assignments=assignments,
            locks=locks,
        )
        raw_result["partial"] = any(
            item.get("partial") for item in raw_result["carriers"]
        )
        return normalize_extract_carrier_facts_result(raw_result)
    except Exception as exc:
        raw_result["diagnostics"].append({"code": "tool-error", "message": str(exc)})
        raw_result["partial"] = True
        return normalize_extract_carrier_facts_result(raw_result)


@register_tool
def extract_size_flow_facts(
    func: Annotated[
        str,
        "Target function address or name. The tool resolves it to function_ea and decompiles one function only.",
    ],
    filters: (
        Annotated[
            dict[str, Any],
            "Optional generic filters. v1 accepts max_instructions for degraded disassembly windows and reports partial diagnostics instead of dropping uncertain facts.",
        ]
        | None
    ) = None,
) -> dict:
    """Extract generic size/source/transform/guard/allocation/access facts.

    This is a structured fact extractor for OOB/integer-overflow analysis, not
    an OOB verdict. It does not decide whether a write is exploitable or safe.

    Scope: v1 is best-effort intraprocedural extraction from Hex-Rays
    pseudocode, with a degraded AArch64 disassembly fallback when decompilation
    fails. It extracts function-arg and parser/read size sources,
    arithmetic/cast/align transforms, guard expressions, allocation sinks,
    write/read access sinks, and custom allocator state updates when visible.

    Output semantics: every fact carries expression text, source_refs,
    confidence, partial, and unavailable_reason. dominance=unknown and
    allocation_ref_status=unknown are explicit degraded states, not failures.
    unknown trust_boundary must not be treated as trusted by evidence/verdict
    stages.

    Limitations: no complete SSA, taint, dominance, alias, or custom allocator
    proof. The tool never emits TP/FP/UNCERTAIN and never hard-codes format or
    product names.
    """
    raw_result: dict[str, Any] = {
        "tool": "extract_size_flow_facts",
        "function_ea": None,
        "function_name": "",
        "size_sources": [],
        "size_transforms": [],
        "guards": [],
        "allocation_sinks": [],
        "access_sinks": [],
        "custom_allocator_state": [],
        "diagnostics": [],
        "partial": False,
    }
    try:
        import ida_hexrays

        filters = filters or {}
        try:
            max_instructions = int(filters.get("max_instructions") or 500)
        except (TypeError, ValueError):
            max_instructions = 500
        max_instructions = max(100, min(max_instructions, 5000))
        function_ea, function_name = _resolve_function(func)
        raw_result["function_ea"] = hex(function_ea)
        raw_result["function_name"] = function_name
        raw_result["raw_name"] = function_name

        try:
            cfunc = ida_hexrays.decompile(function_ea)
        except Exception as exc:
            raw_result["diagnostics"].append(
                {"code": "decompile-failed", "message": str(exc)}
            )
            disasm_lines = _disasm_function_lines(
                function_ea, max_instructions=max_instructions
            )
            if disasm_lines:
                raw_result.update(
                    _extract_size_flow_facts_from_disasm(
                        function_ea, function_name, disasm_lines
                    )
                )
                raw_result["diagnostics"].append(
                    {
                        "code": "disasm-fallback-used",
                        "message": "Hex-Rays decompilation failed; emitted low-confidence disassembly facts",
                        "max_instructions": max_instructions,
                    }
                )
            raw_result["partial"] = True
            return normalize_extract_size_flow_facts_result(raw_result)

        if not cfunc:
            raw_result["diagnostics"].append(
                {"code": "decompile-failed", "message": "Decompilation failed"}
            )
            disasm_lines = _disasm_function_lines(
                function_ea, max_instructions=max_instructions
            )
            if disasm_lines:
                raw_result.update(
                    _extract_size_flow_facts_from_disasm(
                        function_ea, function_name, disasm_lines
                    )
                )
                raw_result["diagnostics"].append(
                    {
                        "code": "disasm-fallback-used",
                        "message": "Hex-Rays decompilation failed; emitted low-confidence disassembly facts",
                        "max_instructions": max_instructions,
                    }
                )
            raw_result["partial"] = True
            return normalize_extract_size_flow_facts_result(raw_result)

        raw_result.update(
            _extract_size_flow_facts_from_code(function_ea, function_name, str(cfunc))
        )
        disasm_lines = _disasm_function_lines(
            function_ea, max_instructions=max_instructions
        )
        if disasm_lines:
            disasm_overlay = _extract_size_flow_facts_from_disasm(
                function_ea, function_name, disasm_lines
            )
            if _merge_size_flow_fact_lists(raw_result, disasm_overlay):
                raw_result["diagnostics"].append(
                    {
                        "code": "disasm-overlay-used",
                        "message": "Merged low-confidence disassembly facts with Hex-Rays pseudocode facts",
                        "max_instructions": max_instructions,
                    }
                )
        raw_result["partial"] = (
            any(item.get("partial") for item in raw_result["size_sources"])
            or any(item.get("partial") for item in raw_result["size_transforms"])
            or any(item.get("partial") for item in raw_result["guards"])
            or any(item.get("partial") for item in raw_result["allocation_sinks"])
            or any(item.get("partial") for item in raw_result["access_sinks"])
            or any(item.get("partial") for item in raw_result["custom_allocator_state"])
        )
        return normalize_extract_size_flow_facts_result(raw_result)
    except Exception as exc:
        raw_result["diagnostics"].append({"code": "tool-error", "message": str(exc)})
        raw_result["partial"] = True
        return normalize_extract_size_flow_facts_result(raw_result)


@register_tool
def trace_parameter(
    func: Annotated[str, "目标函数地址或名称"],
    param_index: Annotated[int, "参数索引（0-based）"],
    direction: Annotated[str, "追踪方向：backward"] = "backward",
    max_depth: Annotated[int, "跨调用链最大追踪深度"] = 3,
    max_callers_per_level: Annotated[int, "每层最多分析调用者数量"] = 20,
) -> dict:
    """Heuristic parameter trace (not strict SSA/taint; may miss complex expr, function-pointer and cross-BB paths)"""
    try:
        import ida_funcs
        import ida_hexrays
        import idautils

        if direction != "backward":
            return {
                "func": func,
                "param_index": param_index,
                "direction": direction,
                "paths": [],
                "error": "Only backward direction is currently supported",
            }

        target_start, target_name = _resolve_function(func)
        proto = get_function_prototype(hex(target_start))
        proto_params = proto.get("params") if isinstance(proto, dict) else []
        if not isinstance(proto_params, list):
            proto_params = []
        param_name = (
            proto_params[param_index]["name"]
            if 0 <= param_index < len(proto_params)
            else f"arg{param_index}"
        )

        def _trace_backward(
            current_start: int,
            current_name: str,
            current_param_index: int,
            depth: int,
            visited: set[tuple[int, int]],
        ) -> list[list[dict]]:
            if depth >= max_depth:
                return []
            key = (current_start, current_param_index)
            if key in visited:
                return []
            visited.add(key)

            callees_names = [current_name]
            if "::" in current_name:
                callees_names.append(current_name.split("::")[-1])

            paths_out: list[list[dict]] = []
            caller_count = 0
            for xref in idautils.XrefsTo(current_start):
                if caller_count >= max_callers_per_level:
                    break
                caller_count += 1

                caller_fn = ida_funcs.get_func(xref.frm)
                if not caller_fn:
                    continue
                caller_start = caller_fn.start_ea
                caller_name = ida_funcs.get_func_name(caller_start)

                try:
                    caller_cfunc = ida_hexrays.decompile(caller_start)
                    if not caller_cfunc:
                        continue
                except Exception:
                    continue

                caller_code = str(caller_cfunc)
                lines = caller_code.splitlines()
                call_hits = _extract_call_candidates(caller_code, callees_names)
                if not call_hits:
                    continue

                for hit in call_hits:
                    if current_param_index >= len(hit["args"]):
                        continue

                    arg_expr = hit["args"][current_param_index].strip()
                    assignment_chain = _extract_assignment_chain(
                        lines, hit["line_no"], arg_expr
                    )

                    step = {
                        "callee": {"addr": hex(current_start), "name": current_name},
                        "caller": {"addr": hex(caller_start), "name": caller_name},
                        "call_site": hex(xref.frm),
                        "line": hit["line_no"],
                        "call": hit["line_text"],
                        "argument": arg_expr,
                        "assignment_chain": assignment_chain,
                    }
                    paths_out.append([step])

                    # If argument is caller parameter, recurse to upper callers.
                    if depth + 1 < max_depth and re.match(r"^[A-Za-z_]\w*$", arg_expr):
                        caller_proto = get_function_prototype(hex(caller_start))
                        caller_params = (
                            caller_proto.get("params")
                            if isinstance(caller_proto, dict)
                            else []
                        )
                        if isinstance(caller_params, list):
                            next_index = None
                            for p in caller_params:
                                if p.get("name") == arg_expr:
                                    next_index = p.get("index")
                                    break
                            if isinstance(next_index, int):
                                sub_paths = _trace_backward(
                                    caller_start,
                                    caller_name,
                                    next_index,
                                    depth + 1,
                                    visited,
                                )
                                for sp in sub_paths:
                                    paths_out.append([step] + sp)

            return paths_out

        visited_pairs: set[tuple[int, int]] = set()
        traced_paths = _trace_backward(
            target_start, target_name, param_index, 0, visited_pairs
        )

        return {
            "func": func,
            "resolved_addr": hex(target_start),
            "function": target_name,
            "param_index": param_index,
            "param_name": param_name,
            "direction": direction,
            "max_depth": max_depth,
            "paths": traced_paths,
            "count": len(traced_paths),
            "error": None,
        }
    except Exception as e:
        return {
            "func": func,
            "resolved_addr": None,
            "function": None,
            "param_index": param_index,
            "param_name": None,
            "direction": direction,
            "max_depth": max_depth,
            "paths": [],
            "count": 0,
            "error": str(e),
        }


@register_tool
def get_data_flow(
    func: Annotated[str, "目标函数地址或名称"],
    param_index: Annotated[int, "参数索引（0-based）"],
    direction: Annotated[str, "追踪方向：backward"] = "backward",
    max_depth: Annotated[int, "跨调用链最大追踪深度"] = 3,
    max_callers_per_level: Annotated[int, "每层最多分析调用者数量"] = 20,
) -> dict:
    """Alias of trace_parameter (same heuristic limits: non-SSA/non-taint, may miss complex paths)"""
    return trace_parameter(
        func=func,
        param_index=param_index,
        direction=direction,
        max_depth=max_depth,
        max_callers_per_level=max_callers_per_level,
    )


@register_tool
def list_funcs(
    filter: Annotated[str, "Glob 模式过滤函数名"] = "",
    offset: Annotated[int, "分页偏移量"] = 0,
    count: Annotated[int, "返回结果数量"] = 50,
) -> dict:
    """List functions in the binary with optional filtering and pagination"""
    try:
        import fnmatch

        import ida_funcs
        import idautils

        funcs = []
        skipped = 0
        total = 0

        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea)
            if filter and not fnmatch.fnmatch(name, filter):
                continue

            total += 1
            if skipped < offset:
                skipped += 1
                continue

            if len(funcs) >= count:
                continue  # 继续计算总数

            fn = ida_funcs.get_func(ea)
            size = fn.size() if fn else 0
            funcs.append(
                {
                    "addr": hex(ea),
                    "name": name,
                    "size": size,
                }
            )

        return {
            "data": funcs,
            "offset": offset,
            "count": len(funcs),
            "total": total,
            "more": offset + len(funcs) < total,
        }
    except Exception as e:
        return {
            "data": [],
            "offset": offset,
            "count": 0,
            "total": 0,
            "more": False,
            "error": str(e),
        }


@register_tool
def disasm(
    addr: Annotated[str, "起始地址或函数名"],
    max_instructions: Annotated[int, "最大反汇编指令数"] = 50,
) -> dict:
    """Disassemble instructions at the given address"""
    try:
        import ida_funcs
        import ida_lines
        import ida_ua

        start = parse_address(addr)
        requested_start = start

        # 尝试获取函数边界
        fn = ida_funcs.get_func(start)
        if fn:
            end = fn.end_ea
        else:
            end = None

        lines = []
        ea = requested_start
        for _ in range(max_instructions):
            if end is not None and ea >= end:
                break

            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0:
                break

            disasm_text = ida_lines.generate_disasm_line(ea, 0)
            disasm_text = ida_lines.tag_remove(disasm_text)

            lines.append(
                {
                    "addr": hex(ea),
                    "text": disasm_text,
                    "size": length,
                }
            )

            ea = ea + length

        func_name = None
        if fn:
            func_name = ida_funcs.get_func_name(fn.start_ea)

        return {
            "addr": addr,
            "function": func_name,
            "lines": lines,
            "count": len(lines),
            "error": None,
        }
    except Exception as e:
        return {
            "addr": addr,
            "function": None,
            "lines": [],
            "count": 0,
            "error": str(e),
        }


@register_tool
def xrefs_to(
    addrs: Annotated[str, "目标地址列表（逗号分隔或单个地址）"],
    limit: Annotated[int, "每个地址的最大交叉引用数（默认 100，最大 1000）"] = 100,
) -> list:
    """Get cross-references to specified addresses"""
    addr_list = normalize_list_input(addrs)

    if limit <= 0 or limit > 1000:
        limit = 1000

    results = []
    for addr in addr_list:
        try:
            import ida_funcs
            import idautils

            ea = parse_address(addr)
            xrefs = []
            more = False

            for xref in idautils.XrefsTo(ea):
                if len(xrefs) >= limit:
                    more = True
                    break

                fn = ida_funcs.get_func(xref.frm)
                fn_info = None
                if fn:
                    fn_info = {
                        "addr": hex(fn.start_ea),
                        "name": ida_funcs.get_func_name(fn.start_ea),
                    }

                xrefs.append(
                    {
                        "addr": hex(xref.frm),
                        "type": "code" if xref.iscode else "data",
                        "fn": fn_info,
                    }
                )

            results.append({"addr": addr, "xrefs": xrefs, "more": more})
        except Exception as e:
            results.append({"addr": addr, "xrefs": None, "error": str(e)})

    return results


@register_tool
def callees(
    addrs: Annotated[str, "函数地址列表（逗号分隔或单个地址）"],
    limit: Annotated[int, "每个函数的最大被调用数（默认 200，最大 500）"] = 200,
) -> list:
    """Get functions called by the specified functions"""
    addr_list = normalize_list_input(addrs)

    if limit <= 0 or limit > 500:
        limit = 500

    results = []
    for fn_addr in addr_list:
        try:
            import ida_idp
            import ida_name
            import ida_ua
            import idaapi

            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append(
                    {"addr": fn_addr, "callees": None, "error": "No function found"}
                )
                continue

            func_end = func.end_ea
            callees_dict = {}
            more = False
            current_ea = func_start

            while current_ea < func_end:
                if len(callees_dict) >= limit:
                    more = True
                    break

                insn = ida_ua.insn_t()
                length = ida_ua.decode_insn(insn, current_ea)
                if length <= 0:
                    # 跳到下一个有效地址
                    next_ea = idaapi.next_head(current_ea, func_end)
                    if next_ea == idaapi.BADADDR:
                        break
                    current_ea = next_ea
                    continue

                # 使用与架构无关的调用指令检测
                if ida_idp.is_call_insn(insn):
                    op0 = insn.ops[0]
                    if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                        target = op0.addr
                    elif op0.type == ida_ua.o_imm:
                        target = op0.value
                    else:
                        target = None

                    if target is not None and target not in callees_dict:
                        func_type = (
                            "internal" if idaapi.get_func(target) else "external"
                        )
                        func_name = ida_name.get_name(target)
                        if func_name is not None:
                            callees_dict[target] = {
                                "addr": hex(target),
                                "name": func_name,
                                "type": func_type,
                            }

                next_ea = idaapi.next_head(current_ea, func_end)
                if next_ea == idaapi.BADADDR:
                    break
                current_ea = next_ea

            results.append(
                {
                    "addr": fn_addr,
                    "callees": list(callees_dict.values()),
                    "more": more,
                }
            )
        except Exception as e:
            results.append({"addr": fn_addr, "callees": None, "error": str(e)})

    return results


@register_tool
def find_bytes(
    patterns: Annotated[str, "字节模式（如 '48 8B ?? ??'），支持通配符 ??"],
    limit: Annotated[int, "每个模式的最大匹配数（默认 1000，最大 10000）"] = 1000,
    offset: Annotated[int, "跳过前 N 个匹配结果"] = 0,
) -> list:
    """Search for byte patterns in the binary (supports wildcards with ??)"""
    pattern_list = normalize_list_input(patterns)

    if limit <= 0 or limit > 10000:
        limit = 10000

    results = []
    for pattern in pattern_list:
        matches = []
        skipped = 0
        more = False
        try:
            import ida_bytes
            import ida_ida
            import idaapi

            compiled = ida_bytes.compiled_binpat_vec_t()
            err = ida_bytes.parse_binpat_str(
                compiled, ida_ida.inf_get_min_ea(), pattern, 16
            )
            if err:
                results.append(
                    {
                        "pattern": pattern,
                        "matches": [],
                        "n": 0,
                        "cursor": {"done": True},
                    }
                )
                continue

            ea = ida_ida.inf_get_min_ea()
            max_ea = ida_ida.inf_get_max_ea()

            while ea != idaapi.BADADDR:
                ea = ida_bytes.bin_search(
                    ea, max_ea, compiled, ida_bytes.BIN_SEARCH_FORWARD
                )
                if ea != idaapi.BADADDR:
                    if skipped < offset:
                        skipped += 1
                    else:
                        matches.append(hex(ea))
                        if len(matches) >= limit:
                            next_ea = ida_bytes.bin_search(
                                ea + 1, max_ea, compiled, ida_bytes.BIN_SEARCH_FORWARD
                            )
                            more = next_ea != idaapi.BADADDR
                            break
                    ea += 1
        except Exception:
            pass

        results.append(
            {
                "pattern": pattern,
                "matches": matches,
                "n": len(matches),
                "cursor": {"next": offset + limit} if more else {"done": True},
            }
        )

    return results


@register_tool
def imports(
    offset: Annotated[int, "分页偏移量"] = 0,
    count: Annotated[int, "返回数量（0=全部）"] = 0,
) -> dict:
    """List imported symbols from the binary"""
    try:
        import ida_nalt

        nimps = ida_nalt.get_import_module_qty()
        all_imports = []

        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            if not module_name:
                module_name = "<unnamed>"

            def imp_cb(ea, symbol_name, ordinal, acc=all_imports, mod=module_name):
                if not symbol_name:
                    symbol_name = f"#{ordinal}"
                acc.append(
                    {
                        "addr": hex(ea),
                        "name": symbol_name,
                        "module": mod,
                    }
                )
                return True

            ida_nalt.enum_import_names(i, imp_cb)

        total = len(all_imports)
        if count > 0:
            data = all_imports[offset : offset + count]
        else:
            data = all_imports[offset:]

        return {
            "data": data,
            "offset": offset,
            "count": len(data),
            "total": total,
            "more": offset + len(data) < total,
        }
    except Exception as e:
        return {
            "data": [],
            "offset": offset,
            "count": 0,
            "total": 0,
            "more": False,
            "error": str(e),
        }


@register_tool
def list_globals(
    filter: Annotated[str, "Glob 模式过滤全局变量名"] = "",
    offset: Annotated[int, "分页偏移量"] = 0,
    count: Annotated[int, "返回结果数量"] = 50,
) -> dict:
    """List global variables (non-function named addresses) with optional filtering"""
    try:
        import fnmatch

        import idaapi
        import idautils

        globals_list = []
        skipped = 0
        total = 0

        for addr, name in idautils.Names():
            # 排除函数地址
            if idaapi.get_func(addr):
                continue
            if name is None:
                continue
            if filter and not fnmatch.fnmatch(name, filter):
                continue

            total += 1
            if skipped < offset:
                skipped += 1
                continue
            if len(globals_list) >= count:
                continue

            globals_list.append(
                {
                    "addr": hex(addr),
                    "name": name,
                }
            )

        return {
            "data": globals_list,
            "offset": offset,
            "count": len(globals_list),
            "total": total,
            "more": offset + len(globals_list) < total,
        }
    except Exception as e:
        return {
            "data": [],
            "offset": offset,
            "count": 0,
            "total": 0,
            "more": False,
            "error": str(e),
        }


@register_tool
def list_plt_stubs(
    filter: Annotated[str, "Glob 模式过滤 PLT stub 名称"] = "",
    offset: Annotated[int, "分页偏移量"] = 0,
    count: Annotated[int, "返回结果数量"] = 50,
) -> dict:
    """List PLT (Procedure Linkage Table) stubs and external function references"""
    try:
        import fnmatch

        import ida_segment
        import idaapi
        import idautils

        plt_stubs = []
        skipped = 0
        total = 0

        # 遍历所有命名地址，查找 PLT stubs 和外部引用
        for addr, name in idautils.Names():
            if name is None:
                continue

            # 检查是否在 PLT 段或标记为外部
            seg = ida_segment.getseg(addr)
            seg_name = ida_segment.get_segm_name(seg) if seg else ""

            # 判断是否为 PLT stub 或外部引用
            is_plt = seg_name in [".plt", ".plt.got", ".plt.sec"]

            # 检查是否为导入函数（不是常规函数）
            func = idaapi.get_func(addr)
            is_import_stub = func and (func.flags & idaapi.FUNC_THUNK) != 0
            is_extern = is_import_stub or name.startswith(".")

            if not (is_plt or is_extern or is_import_stub):
                continue

            if filter and not fnmatch.fnmatch(name, filter):
                continue

            total += 1
            if skipped < offset:
                skipped += 1
                continue
            if len(plt_stubs) >= count:
                continue

            # 获取函数类型信息
            func_type = "unknown"
            if is_plt:
                func_type = "plt"
            elif is_import_stub:
                func_type = "thunk"
            elif is_extern:
                func_type = "extern"

            plt_stubs.append(
                {
                    "addr": hex(addr),
                    "name": name,
                    "segment": seg_name,
                    "type": func_type,
                }
            )

        return {
            "data": plt_stubs,
            "offset": offset,
            "count": len(plt_stubs),
            "total": total,
            "more": offset + len(plt_stubs) < total,
        }
    except Exception as e:
        return {
            "data": [],
            "offset": offset,
            "count": 0,
            "total": 0,
            "more": False,
            "error": str(e),
        }


@register_tool
def list_all_names(
    filter: Annotated[str, "Glob 模式过滤符号名称"] = "",
    offset: Annotated[int, "分页偏移量"] = 0,
    count: Annotated[int, "返回结果数量"] = 50,
) -> dict:
    """List all named addresses including functions, PLT stubs, globals, and imports"""
    try:
        import fnmatch

        import ida_segment
        import idaapi
        import idautils

        all_names = []
        skipped = 0
        total = 0

        for addr, name in idautils.Names():
            if name is None:
                continue
            if filter and not fnmatch.fnmatch(name, filter):
                continue

            total += 1
            if skipped < offset:
                skipped += 1
                continue
            if len(all_names) >= count:
                continue

            # 确定符号类型
            func = idaapi.get_func(addr)
            seg = ida_segment.getseg(addr)
            seg_name = ida_segment.get_segm_name(seg) if seg else ""

            sym_type = "data"
            if func:
                if func.flags & idaapi.FUNC_THUNK:
                    sym_type = "thunk"
                else:
                    sym_type = "function"
            elif seg_name in [".plt", ".plt.got", ".plt.sec"]:
                sym_type = "plt"
            elif name.startswith("."):
                sym_type = "extern"

            all_names.append(
                {
                    "addr": hex(addr),
                    "name": name,
                    "segment": seg_name,
                    "type": sym_type,
                }
            )

        return {
            "data": all_names,
            "offset": offset,
            "count": len(all_names),
            "total": total,
            "more": offset + len(all_names) < total,
        }
    except Exception as e:
        return {
            "data": [],
            "offset": offset,
            "count": 0,
            "total": 0,
            "more": False,
            "error": str(e),
        }
