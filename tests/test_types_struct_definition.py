"""Tests for type definition tools."""

from __future__ import annotations

import sys
from types import ModuleType

from ida_mcp_stdio.tools.types import get_struct_definition


class _FakeMemberType:
    def __init__(self, text: str, size: int):
        self._text = text
        self._size = size

    def _print(self) -> str:
        return self._text

    def get_size(self) -> int:
        return self._size


class _FakeMember:
    def __init__(self, offset_bytes: int, name: str, typ: _FakeMemberType):
        self._offset_bits = offset_bytes * 8
        self.name = name
        self.type = typ

    def begin(self) -> int:
        return self._offset_bits


class _FakeUDTData(list):
    is_union = False


class _FakeTInfo:
    def __init__(self):
        self._name = None

    def get_named_type(self, _til, name: str) -> bool:
        self._name = name
        return name == "TransData"

    def get_udt_details(self, udt_data: _FakeUDTData) -> bool:
        if self._name != "TransData":
            return False
        udt_data.extend(
            [
                _FakeMember(0x0, "len", _FakeMemberType("uint32_t", 4)),
                _FakeMember(0x4, "payload", _FakeMemberType("char[16]", 16)),
            ]
        )
        return True

    def get_size(self) -> int:
        return 0x14


def _install_fake_ida_typeinf(monkeypatch):
    ida_typeinf = ModuleType("ida_typeinf")
    ida_typeinf.tinfo_t = _FakeTInfo
    ida_typeinf.udt_type_data_t = _FakeUDTData
    monkeypatch.setitem(sys.modules, "ida_typeinf", ida_typeinf)


def test_get_struct_definition_returns_layout_only(monkeypatch):
    _install_fake_ida_typeinf(monkeypatch)

    result = get_struct_definition("TransData")

    assert result["error"] is None
    assert result["struct"] == "TransData"
    assert result["size"] == 0x14
    assert result["cardinality"] == 2
    assert result["members"][0] == {
        "offset": "0x00000000",
        "type": "uint32_t",
        "name": "len",
        "size": 4,
    }
    assert result["members"][1]["offset"] == "0x00000004"
    assert all("value" not in member for member in result["members"])


def test_get_struct_definition_not_found(monkeypatch):
    _install_fake_ida_typeinf(monkeypatch)

    result = get_struct_definition("NoSuchStruct")

    assert result["members"] is None
    assert result["error"] == "Struct 'NoSuchStruct' not found"
