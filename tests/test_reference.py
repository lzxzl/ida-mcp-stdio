from __future__ import annotations

from typing import Annotated

import pytest

from ida_mcp_stdio import reference
from ida_mcp_stdio.tools import ToolDefinition


def test_reference_scans_source_without_importing_it(tmp_path):
    source = tmp_path / "functions.py"
    source.write_text(
        'raise RuntimeError("must not import")\n\ndef decompile(addr: int) -> str:\n    """Read pseudocode for a function."""\n    pass\n'
    )
    result = reference.ReferenceIndex([tmp_path]).search("decompile")
    assert result["entries"][0]["name"] == "functions.decompile"
    assert "addr: int" in result["entries"][0]["signature"]
    assert result["entries"][0]["line"] == 3


def test_reference_returns_bounded_pages(tmp_path):
    (tmp_path / "api.py").write_text(
        "\n".join(
            f'def function_{i}():\n    """Function example."""\n    pass'
            for i in range(6)
        )
    )
    index = reference.ReferenceIndex([tmp_path])
    first = index.search("function", limit=2)
    second = index.search("function", offset=2, limit=2)
    assert first["total"] == 6
    assert len(first["entries"]) == 2
    assert first["next_offset"] == 2
    assert first["entries"][0]["name"] != second["entries"][0]["name"]


def test_union_schema_keeps_alternatives_nullable_and_description():
    def tool(value: Annotated[str | list[str] | None, "items"] = None):
        pass

    definition = ToolDefinition.from_function(tool)
    schema = definition.input_schema["properties"]["value"]
    assert {item["type"] for item in schema["anyOf"]} == {"string", "array", "null"}
    assert schema["description"] == "items"
    assert schema["default"] is None


def test_validation_rejects_boolean_integer_and_unknown_parameters():
    def tool(count: int):
        pass

    definition = ToolDefinition.from_function(tool)
    with pytest.raises(ValueError):
        definition.validate_arguments({"count": True})
    with pytest.raises(ValueError):
        definition.validate_arguments({"count": 3, "surprise": 1})
