"""Tests for decompile analysis tool."""

from __future__ import annotations

import sys
from types import ModuleType

from ida_mcp_stdio.tools.analysis import decompile


def _install_fake_hexrays(monkeypatch):
    """Install a fake ida_hexrays module used by decompile()."""
    ida_hexrays = ModuleType("ida_hexrays")
    calls: list[int] = []

    class _CFunc:
        def __init__(self, text: str):
            self._text = text

        def __str__(self) -> str:
            return self._text

    def _fake_decompile(ea: int):
        calls.append(ea)
        if ea == 0x3000:
            raise RuntimeError("boom")
        if ea == 0x1000:
            return _CFunc("code_1000")
        if ea == 0x2000:
            return _CFunc("code_2000")
        return None

    ida_hexrays.decompile = _fake_decompile
    monkeypatch.setitem(sys.modules, "ida_hexrays", ida_hexrays)
    return calls


def test_decompile_single_addr_returns_dict(monkeypatch):
    calls = _install_fake_hexrays(monkeypatch)

    result = decompile(addr="0x1000")

    assert result["error"] is None
    assert result["addr"] == "0x1000"
    assert result["code"] == "code_1000"
    assert calls == [0x1000]


def test_decompile_batch_csv_returns_list(monkeypatch):
    calls = _install_fake_hexrays(monkeypatch)

    result = decompile(addrs="0x1000,0x2000")

    assert isinstance(result, list)
    assert len(result) == 2
    assert result[0]["addr"] == "0x1000"
    assert result[0]["error"] is None
    assert result[1]["addr"] == "0x2000"
    assert result[1]["error"] is None
    assert calls == [0x1000, 0x2000]


def test_decompile_batch_continues_on_per_item_error(monkeypatch):
    _install_fake_hexrays(monkeypatch)

    result = decompile(addrs=["0x1000", "0x3000", "invalid"])

    assert isinstance(result, list)
    assert len(result) == 3
    assert result[0]["error"] is None
    assert result[1]["error"] == "boom"
    assert "Invalid address" in result[2]["error"]


def test_decompile_requires_addr_or_addrs():
    result = decompile()
    assert result["code"] is None
    assert "required" in result["error"]
