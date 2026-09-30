"""Tests for symbol listing analysis tools."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

from ida_mcp_stdio.tools.analysis import list_plt_stubs


def test_list_plt_stubs_skips_none_name_with_filter(monkeypatch):
    ida_segment = ModuleType("ida_segment")
    idaapi = ModuleType("idaapi")
    idautils = ModuleType("idautils")

    ida_segment.getseg = lambda ea: SimpleNamespace(name=".text")
    ida_segment.get_segm_name = lambda seg: getattr(seg, "name", "")

    idaapi.FUNC_THUNK = 1
    idaapi.get_func = lambda ea: None

    idautils.Names = lambda: [
        (0x1000, None),
        (0x2000, ".extern_func"),
        (0x3000, "normal_func"),
    ]

    monkeypatch.setitem(sys.modules, "ida_segment", ida_segment)
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "idautils", idautils)

    result = list_plt_stubs(filter="*.extern*")

    assert "error" not in result
    assert result["count"] == 1
    assert result["total"] == 1
    assert result["data"][0]["name"] == ".extern_func"
