"""Tool registration system for IDA MCP stdio server."""

from __future__ import annotations

import inspect
import types as python_types
from collections.abc import Callable
from typing import (
    Annotated,
    Any,
    Literal,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)


class ToolDefinition:
    """Protocol-agnostic tool definition."""

    def __init__(
        self,
        func: Callable,
        name: str,
        description: str,
        parameters: dict[str, dict],
        required: list[str],
    ):
        self.func = func
        self.name = name
        self.description = description
        self.parameters = parameters
        self.required = required
        self.signature = inspect.signature(func)
        self.annotations = {
            "readOnlyHint": name
            not in {
                "open_database",
                "close_database",
                "save_database",
                "execute_python",
            },
            "destructiveHint": name in {"open_database", "execute_python"},
            "openWorldHint": name == "execute_python",
        }

    @classmethod
    def from_function(cls, func: Callable) -> ToolDefinition:
        """Create a ToolDefinition from a function's signature and annotations."""
        name = func.__name__
        description = inspect.cleandoc(func.__doc__ or "No description")

        sig = inspect.signature(func)
        try:
            hints = get_type_hints(func, include_extras=True)
        except (NameError, TypeError, ValueError):
            hints = {}

        parameters: dict[str, dict] = {}
        required: list[str] = []

        for param_name, param in sig.parameters.items():
            hint = hints.get(param_name)
            param_schema = _type_to_schema(hint, param_name)

            if param.default is inspect.Parameter.empty:
                required.append(param_name)
            else:
                param_schema["default"] = param.default

            parameters[param_name] = param_schema

        return cls(func, name, description, parameters, required)

    @property
    def input_schema(self) -> dict:
        """JSON Schema for MCP tools/list."""
        return {
            "type": "object",
            "properties": self.parameters,
            "required": self.required,
            "additionalProperties": False,
        }

    def validate_arguments(self, arguments: dict[str, Any]) -> None:
        """Reject invalid bindings and schema values before invoking a tool."""
        try:
            self.signature.bind(**arguments)
        except TypeError as error:
            raise ValueError(str(error)) from error
        for name, value in arguments.items():
            if not _matches_schema(value, self.parameters[name]):
                raise ValueError(f"Invalid value for '{name}': {value!r}")


class ToolsRegistry:
    """Protocol-agnostic tool registry."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, func: Callable) -> Callable:
        """Register a tool function."""
        tool_def = ToolDefinition.from_function(func)
        self._tools[tool_def.name] = tool_def
        return func

    def get_tool(self, name: str) -> ToolDefinition | None:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        """List all registered tools."""
        return list(self._tools.values())

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Call a tool by name with arguments."""
        tool_def = self._tools.get(name)
        if tool_def is None:
            raise KeyError(f"Tool not found: {name}")
        tool_def.validate_arguments(arguments or {})
        return tool_def.func(**(arguments or {}))


# Global registry
_registry = ToolsRegistry()


def register_tool(func: Callable) -> Callable:
    """Decorator to register a function as a tool."""
    return _registry.register(func)


def get_registry() -> ToolsRegistry:
    """Get the global tool registry."""
    return _registry


# Type mapping helpers

_PYTHON_TYPE_TO_JSON: dict[type, str] = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
}


def _type_to_schema(hint: Any, param_name: str) -> dict:
    """Convert a Python type hint to a JSON Schema property."""
    if hint is None:
        return {"type": "string", "description": f"Parameter {param_name}"}

    description = f"Parameter {param_name}"

    # Handle Annotated[type, description]
    origin = get_origin(hint)
    if origin is Annotated:
        args = get_args(hint)
        if len(args) >= 2 and isinstance(args[1], str):
            description = args[1]
        hint = args[0]
        origin = get_origin(hint)

    if origin in (Union, python_types.UnionType):
        return {
            "anyOf": [_type_to_schema(arg, param_name) for arg in get_args(hint)],
            "description": description,
        }
    if origin is Literal:
        values = list(get_args(hint))
        return {"enum": values, "description": description}
    if hint is type(None):
        return {"type": "null", "description": description}
    if hint is Any:
        return {"description": description}

    # Handle basic types
    if isinstance(hint, type):
        json_type = _PYTHON_TYPE_TO_JSON.get(hint, "string")
        return {"type": json_type, "description": description}

    # Handle list[T]
    if origin is list:
        args = get_args(hint)
        if args:
            item_schema = _type_to_schema(args[0], "item")
            return {"type": "array", "items": item_schema, "description": description}
        return {"type": "array", "description": description}

    # Handle dict
    if origin is dict:
        return {"type": "object", "description": description}

    return {"type": "string", "description": description}


def _matches_schema(value: Any, schema: dict) -> bool:
    if "anyOf" in schema:
        return any(_matches_schema(value, item) for item in schema["anyOf"])
    if "enum" in schema:
        return value in schema["enum"]
    kind = schema.get("type")
    checks = {
        "string": lambda: isinstance(value, str),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda: isinstance(value, (int, float))
        and not isinstance(value, bool),
        "boolean": lambda: isinstance(value, bool),
        "null": lambda: value is None,
        "array": lambda: isinstance(value, list)
        and all(_matches_schema(v, schema.get("items", {})) for v in value),
        "object": lambda: isinstance(value, dict),
    }
    return checks[kind]() if kind in checks else True
