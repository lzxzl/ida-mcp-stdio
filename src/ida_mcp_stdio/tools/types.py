"""类型工具模块 - 提供结构体和类型信息查询的 MCP 工具。

包含结构体搜索、结构体读取和函数导出等功能。
"""

from __future__ import annotations

from typing import Annotated

from ..utils import parse_address
from . import register_tool


@register_tool
def search_structs(
    filter: Annotated[str, "大小写不敏感的结构体名称子串"],
) -> list:
    """Search for structure types by name substring"""
    try:
        import ida_typeinf

        results = []
        limit = ida_typeinf.get_ordinal_limit()

        for ordinal in range(1, limit):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(None, ordinal):
                type_name = tif.get_type_name()
                if type_name and filter.lower() in type_name.lower():
                    if tif.is_udt():
                        udt_data = ida_typeinf.udt_type_data_t()
                        cardinality = 0
                        is_union = False
                        if tif.get_udt_details(udt_data):
                            cardinality = udt_data.size()
                            is_union = udt_data.is_union

                        results.append({
                            "name": type_name,
                            "size": tif.get_size(),
                            "cardinality": cardinality,
                            "is_union": is_union,
                            "ordinal": ordinal,
                        })

        return results
    except Exception as e:
        return [{"error": str(e)}]


@register_tool
def read_struct(
    addr: Annotated[str, "读取结构体数据的内存地址"],
    struct: Annotated[str, "结构体类型名称（留空则自动检测）"] = "",
) -> dict:
    """Read struct type definition and parse actual memory values at a given address.

    If struct name is not provided, attempts auto-detection from address type info.
    """
    try:
        import ida_bytes
        import ida_ida
        import ida_nalt
        import ida_typeinf
        import idaapi

        ea = parse_address(addr)
        struct_name = struct

        # 自动检测结构体类型
        if not struct_name:
            tif_auto = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tif_auto, ea) and tif_auto.is_udt():
                struct_name = tif_auto.get_type_name()

        if not struct_name:
            return {
                "addr": addr,
                "struct": None,
                "members": None,
                "error": "No struct specified and could not auto-detect from address",
            }

        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(None, struct_name):
            return {
                "addr": addr,
                "struct": struct_name,
                "members": None,
                "error": f"Struct '{struct_name}' not found",
            }

        udt_data = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt_data):
            return {
                "addr": addr,
                "struct": struct_name,
                "members": None,
                "error": "Failed to get struct details",
            }

        is_64bit = ida_ida.inf_is_64bit()

        members = []
        for member in udt_data:
            member_offset = member.begin() // 8
            member_type = member.type._print()
            member_name = member.name
            member_size = member.type.get_size()
            member_addr = ea + member_offset

            # 根据类型读取内存值
            try:
                if member.type.is_ptr():
                    if is_64bit:
                        value = idaapi.get_qword(member_addr)
                        value_str = f"0x{value:016X}"
                    else:
                        value = idaapi.get_dword(member_addr)
                        value_str = f"0x{value:08X}"
                elif member_size == 1:
                    value = idaapi.get_byte(member_addr)
                    value_str = f"0x{value:02X} ({value})"
                elif member_size == 2:
                    value = idaapi.get_word(member_addr)
                    value_str = f"0x{value:04X} ({value})"
                elif member_size == 4:
                    value = idaapi.get_dword(member_addr)
                    value_str = f"0x{value:08X} ({value})"
                elif member_size == 8:
                    value = idaapi.get_qword(member_addr)
                    value_str = f"0x{value:016X} ({value})"
                else:
                    bytes_data = []
                    for i in range(min(member_size, 16)):
                        try:
                            bytes_data.append(f"{idaapi.get_byte(member_addr + i):02X}")
                        except Exception:
                            break
                    suffix = "..." if member_size > 16 else ""
                    value_str = f"[{' '.join(bytes_data)}{suffix}]"
            except Exception:
                value_str = "<failed to read>"

            members.append({
                "offset": f"0x{member_offset:08X}",
                "type": member_type,
                "name": member_name,
                "size": member_size,
                "value": value_str,
            })

        return {"addr": addr, "struct": struct_name, "members": members, "error": None}
    except Exception as e:
        return {"addr": addr, "struct": struct, "members": None, "error": str(e)}


@register_tool
def export_funcs(
    addrs: Annotated[str, "函数地址列表（逗号分隔或单个地址）"],
    format: Annotated[str, "导出格式：json（完整信息）、c_header（C 头文件）、prototypes（原型列表）"] = "json",
) -> list:
    """Export function information in various formats"""
    from ..utils import normalize_list_input

    addr_list = normalize_list_input(addrs)
    results = []

    for addr in addr_list:
        try:
            import ida_funcs
            import ida_hexrays
            import ida_typeinf
            import idaapi
            import idc

            ea = parse_address(addr)
            fn = idaapi.get_func(ea)
            if not fn:
                results.append({"addr": addr, "error": "No function at address"})
                continue

            func_name = ida_funcs.get_func_name(fn.start_ea)
            func_size = fn.size()

            # 获取函数原型
            tif = ida_typeinf.tinfo_t()
            prototype = None
            if idaapi.get_tinfo(tif, fn.start_ea):
                prototype = tif._print(func_name)

            # 获取注释
            cmt = idc.get_func_cmt(fn.start_ea, 0) or ""
            cmt_rep = idc.get_func_cmt(fn.start_ea, 1) or ""

            func_info = {
                "addr": hex(fn.start_ea),
                "name": func_name,
                "size": func_size,
                "prototype": prototype,
                "comment": cmt,
                "repeatable_comment": cmt_rep,
            }

            if format == "json":
                # 添加反编译代码
                try:
                    cfunc = ida_hexrays.decompile(fn.start_ea)
                    func_info["code"] = str(cfunc) if cfunc else None
                except Exception:
                    func_info["code"] = None

            elif format == "c_header":
                if prototype:
                    func_info["c_header"] = f"{prototype};"
                else:
                    func_info["c_header"] = f"// {func_name} at {hex(fn.start_ea)}"

            elif format == "prototypes":
                func_info["prototype"] = prototype or f"unknown {func_name}(void)"

            results.append(func_info)
        except Exception as e:
            results.append({"addr": addr, "error": str(e)})

    return results
