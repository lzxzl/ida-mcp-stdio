"""内存工具模块 - 提供二进制内存数据读取相关的 MCP 工具。

包含字节读取、整数读取、字符串读取和段数据读取等功能。
"""

from __future__ import annotations

import re
from typing import Annotated

from ..utils import normalize_list_input, parse_address
from . import register_tool

_INT_CLASS_RE = re.compile(r"^(?P<sign>[iu])(?P<bits>8|16|32|64)(?P<endian>le|be)?$")


def _parse_int_class(text: str) -> tuple[int, bool, str, str]:
    """解析整数类型字符串。

    Args:
        text: 整数类型（如 i8, u64, i16le, i32be）

    Returns:
        (bits, signed, byte_order, normalized) 元组
    """
    if not text:
        raise ValueError("Missing integer class")

    cleaned = text.strip().lower()
    match = _INT_CLASS_RE.match(cleaned)
    if not match:
        raise ValueError(f"Invalid integer class: {text}")

    bits = int(match.group("bits"))
    signed = match.group("sign") == "i"
    endian = match.group("endian") or "le"
    byte_order = "little" if endian == "le" else "big"
    normalized = f"{'i' if signed else 'u'}{bits}{endian}"
    return bits, signed, byte_order, normalized


@register_tool
def get_bytes(
    addr: Annotated[str, "读取起始地址"],
    size: Annotated[int, "读取字节数"],
) -> dict:
    """Read raw bytes from memory at the specified address"""
    try:
        import ida_bytes

        ea = parse_address(addr)
        data = ida_bytes.get_bytes(ea, size)
        if not data:
            return {"addr": addr, "data": None, "error": f"Failed to read {size} bytes at {addr}"}

        hex_str = " ".join(f"{b:02x}" for b in data)
        return {"addr": addr, "size": size, "data": hex_str, "error": None}
    except Exception as e:
        return {"addr": addr, "size": size, "data": None, "error": str(e)}


@register_tool
def get_int(
    addr: Annotated[str, "读取地址"],
    ty: Annotated[str, "整数类型（i8/u8/i16le/i16be/i32le/i32be/i64le/i64be/u16le 等）"],
) -> dict:
    """Read an integer value from memory with specified type format"""
    try:
        import ida_bytes

        bits, signed, byte_order, normalized = _parse_int_class(ty)
        ea = parse_address(addr)
        size = bits // 8
        data = ida_bytes.get_bytes(ea, size)

        if not data or len(data) != size:
            return {"addr": addr, "ty": ty, "value": None, "error": f"Failed to read {size} bytes at {addr}"}

        value = int.from_bytes(data, byte_order, signed=signed)
        return {"addr": addr, "ty": normalized, "value": value, "error": None}
    except Exception as e:
        return {"addr": addr, "ty": ty, "value": None, "error": str(e)}


@register_tool
def get_string(
    addrs: Annotated[str, "读取字符串的地址列表（逗号分隔或单个地址）"],
) -> list:
    """Read strings from memory addresses"""
    addr_list = normalize_list_input(addrs)
    results = []

    for addr in addr_list:
        try:
            import idaapi

            ea = parse_address(addr)
            raw = idaapi.get_strlit_contents(ea, -1, 0)
            if not raw:
                results.append({"addr": addr, "value": None, "error": "No string at address"})
                continue
            value = raw.decode("utf-8", errors="replace")
            results.append({"addr": addr, "value": value, "error": None})
        except Exception as e:
            results.append({"addr": addr, "value": None, "error": str(e)})

    return results


@register_tool
def get_segment_bytes(
    name: Annotated[str, "段名称（如 .text, .data, .rodata）"],
    max_size: Annotated[int, "最大读取字节数（默认 65536）"] = 65536,
) -> dict:
    """Read all bytes from a named segment"""
    try:
        import ida_segment

        seg = ida_segment.get_segm_by_name(name)
        if not seg:
            return {"name": name, "data": None, "error": f"Segment '{name}' not found"}

        import ida_bytes

        size = min(seg.size(), max_size)
        data = ida_bytes.get_bytes(seg.start_ea, size)
        if not data:
            return {"name": name, "data": None, "error": f"Failed to read segment '{name}'"}

        hex_str = " ".join(f"{b:02x}" for b in data)
        return {
            "name": name,
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": seg.size(),
            "read_size": size,
            "data": hex_str,
            "truncated": size < seg.size(),
            "error": None,
        }
    except Exception as e:
        return {"name": name, "data": None, "error": str(e)}
