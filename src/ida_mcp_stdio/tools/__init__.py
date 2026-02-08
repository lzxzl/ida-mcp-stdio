"""Tool registration system for IDA MCP stdio server."""

from __future__ import annotations

import inspect
from typing import Annotated, Any, Callable, Optional, get_args, get_origin, get_type_hints


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

    @classmethod
    def from_function(cls, func: Callable) -> ToolDefinition:
        """Create a ToolDefinition from a function's signature and annotations."""
        name = func.__name__
        description = (func.__doc__ or "No description").strip().split("\n")[0]

        sig = inspect.signature(func)
        try:
            hints = get_type_hints(func, include_extras=True)
        except Exception:
            hints = {}

        parameters: dict[str, dict] = {}
        required: list[str] = []

        for param_name, param in sig.parameters.items():
            hint = hints.get(param_name)
            param_schema = _type_to_schema(hint, param_name)

            if param.default is inspect.Parameter.empty:
                required.append(param_name)

            parameters[param_name] = param_schema

        return cls(func, name, description, parameters, required)

    @property
    def input_schema(self) -> dict:
        """JSON Schema for MCP tools/list."""
        return {
            "type": "object",
            "properties": self.parameters,
            "required": self.required,
        }


class ToolsRegistry:
    """Protocol-agnostic tool registry."""

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, func: Callable) -> Callable:
        """Register a tool function."""
        tool_def = ToolDefinition.from_function(func)
        self._tools[tool_def.name] = tool_def
        return func

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
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

    # Handle Optional[T] -> T with nullable note
    if origin is Optional or (origin is type(int | str) if hasattr(type(int | str), '__mro__') else False):
        pass  # keep as-is for now

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

    # Handle Union types (e.g., str | int)
    try:
        import types
        if isinstance(hint, types.UnionType):
            # For union types, use the first non-None type
            union_args = get_args(hint)
            for arg in union_args:
                if arg is not type(None):
                    return _type_to_schema(arg, param_name)
    except (AttributeError, TypeError):
        pass

    return {"type": "string", "description": description}
