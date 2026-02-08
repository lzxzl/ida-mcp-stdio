"""Utility functions for IDA MCP stdio server."""

from __future__ import annotations

from typing import Any


class IDAError(Exception):
    """IDA-specific error."""
    pass


def parse_address(addr: str | int) -> int:
    """Parse an address string to integer.

    Supported formats:
    - Hexadecimal: 0x401000, 0X401000, 401000h
    - Decimal: 4198400
    - Symbol names: resolved via idalib (when available)

    Args:
        addr: Address as string or integer.

    Returns:
        Integer address.

    Raises:
        ValueError: If the address cannot be parsed.
    """
    if isinstance(addr, int):
        return addr

    addr_str = str(addr).strip()
    if not addr_str:
        raise ValueError("Empty address string")

    # Hex with 0x prefix
    if addr_str.startswith(("0x", "0X")):
        try:
            return int(addr_str, 16)
        except ValueError:
            raise ValueError(f"Invalid hex address: {addr_str}")

    # Hex with h suffix
    if addr_str.endswith(("h", "H")):
        try:
            return int(addr_str[:-1], 16)
        except ValueError:
            raise ValueError(f"Invalid hex address: {addr_str}")

    # Try decimal
    try:
        return int(addr_str, 10)
    except ValueError:
        pass

    # Try symbol name resolution via idalib
    try:
        import idaapi
        import ida_name

        ea = ida_name.get_name_ea(idaapi.BADADDR, addr_str)
        if ea != idaapi.BADADDR:
            return ea
    except ImportError:
        pass

    raise ValueError(f"Invalid address: {addr_str}")


def normalize_list_input(value: Any) -> list:
    """Normalize input to a list.

    - If already a list, return as-is.
    - If a comma-separated string, split and strip.
    - Otherwise, wrap in a list.

    Args:
        value: Input value to normalize.

    Returns:
        Normalized list.
    """
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]
