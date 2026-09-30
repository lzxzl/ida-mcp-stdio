"""Tests for disassembly analysis tools."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

from ida_mcp_stdio.tools.analysis import disasm


def _install_fake_ida_modules(monkeypatch):
    """Install minimal fake IDA modules used by disasm()."""
    ida_funcs = ModuleType("ida_funcs")
    ida_lines = ModuleType("ida_lines")
    ida_ua = ModuleType("ida_ua")

    fn = SimpleNamespace(start_ea=0x6A9C, end_ea=0x7100)
    lengths = {
        0x6E7C: 4,
        0x6E80: 4,
        0x6E84: 4,
    }

    ida_funcs.get_func = lambda ea: fn if fn.start_ea <= ea < fn.end_ea else None
    ida_funcs.get_func_name = lambda ea: "target_fn" if ea == fn.start_ea else ""

    ida_lines.generate_disasm_line = lambda ea, flags: f"insn_{ea:x}"
    ida_lines.tag_remove = lambda text: text

    class _Insn:
        pass

    ida_ua.insn_t = _Insn
    ida_ua.decode_insn = lambda insn, ea: lengths.get(ea, 0)

    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)
    monkeypatch.setitem(sys.modules, "ida_lines", ida_lines)
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)


def test_disasm_starts_from_requested_address_inside_function(monkeypatch):
    _install_fake_ida_modules(monkeypatch)

    result = disasm(addr="0x6e7c", max_instructions=2)

    assert result["error"] is None
    assert result["function"] == "target_fn"
    assert result["count"] == 2
    assert result["lines"][0]["addr"] == "0x6e7c"
    assert result["lines"][1]["addr"] == "0x6e80"
