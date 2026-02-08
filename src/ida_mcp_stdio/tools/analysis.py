"""分析工具模块 - 提供二进制文件分析相关的 MCP 工具。

包含反编译、反汇编、函数列表、交叉引用、调用分析、字节搜索、
导入符号和全局变量等核心分析功能。
"""

from __future__ import annotations

from typing import Annotated

from ..utils import normalize_list_input, parse_address
from . import register_tool


@register_tool
def decompile(addr: Annotated[str, "函数地址或名称"]) -> dict:
    """Decompile a function to pseudocode"""
    try:
        import ida_hexrays

        start = parse_address(addr)
        cfunc = ida_hexrays.decompile(start)
        if not cfunc:
            return {"addr": addr, "code": None, "error": "Decompilation failed"}
        return {"addr": addr, "code": str(cfunc), "error": None}
    except Exception as e:
        return {"addr": addr, "code": None, "error": str(e)}


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
            funcs.append({
                "addr": hex(ea),
                "name": name,
                "size": size,
            })

        return {
            "data": funcs,
            "offset": offset,
            "count": len(funcs),
            "total": total,
            "more": offset + len(funcs) < total,
        }
    except Exception as e:
        return {"data": [], "offset": offset, "count": 0, "total": 0, "more": False, "error": str(e)}


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

        # 尝试获取函数边界
        fn = ida_funcs.get_func(start)
        if fn:
            start = fn.start_ea
            end = fn.end_ea
        else:
            end = None

        lines = []
        ea = start
        for _ in range(max_instructions):
            if end is not None and ea >= end:
                break

            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length <= 0:
                break

            disasm_text = ida_lines.generate_disasm_line(ea, 0)
            disasm_text = ida_lines.tag_remove(disasm_text)

            lines.append({
                "addr": hex(ea),
                "text": disasm_text,
                "size": length,
            })

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
        return {"addr": addr, "function": None, "lines": [], "count": 0, "error": str(e)}


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

                xrefs.append({
                    "addr": hex(xref.frm),
                    "type": "code" if xref.iscode else "data",
                    "fn": fn_info,
                })

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
            import ida_funcs
            import ida_idp
            import ida_name
            import ida_ua
            import idaapi

            func_start = parse_address(fn_addr)
            func = idaapi.get_func(func_start)
            if not func:
                results.append({"addr": fn_addr, "callees": None, "error": "No function found"})
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
                        func_type = "internal" if idaapi.get_func(target) else "external"
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

            results.append({
                "addr": fn_addr,
                "callees": list(callees_dict.values()),
                "more": more,
            })
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
                results.append({
                    "pattern": pattern,
                    "matches": [],
                    "n": 0,
                    "cursor": {"done": True},
                })
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

        results.append({
            "pattern": pattern,
            "matches": matches,
            "n": len(matches),
            "cursor": {"next": offset + limit} if more else {"done": True},
        })

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
                acc.append({
                    "addr": hex(ea),
                    "name": symbol_name,
                    "module": mod,
                })
                return True

            ida_nalt.enum_import_names(i, imp_cb)

        total = len(all_imports)
        if count > 0:
            data = all_imports[offset:offset + count]
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
        return {"data": [], "offset": offset, "count": 0, "total": 0, "more": False, "error": str(e)}


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

            globals_list.append({
                "addr": hex(addr),
                "name": name,
            })

        return {
            "data": globals_list,
            "offset": offset,
            "count": len(globals_list),
            "total": total,
            "more": offset + len(globals_list) < total,
        }
    except Exception as e:
        return {"data": [], "offset": offset, "count": 0, "total": 0, "more": False, "error": str(e)}
