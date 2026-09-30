"""Composable Python execution inside an IDA worker; this is not a sandbox."""

from __future__ import annotations

import ast
import asyncio
import contextlib
import inspect
import io
import time
import traceback
from typing import Any


class _Capture(io.TextIOBase):
    def __init__(self, limit: int):
        self.remaining = limit
        self.parts: list[str] = []
        self.truncated = False

    def write(self, value: str) -> int:
        encoded = value.encode("utf-8", errors="replace")
        part = encoded[: self.remaining].decode("utf-8", errors="ignore")
        self.parts.append(part)
        self.remaining -= len(part.encode("utf-8"))
        self.truncated |= len(encoded) > len(part.encode("utf-8"))
        return len(value)

    def getvalue(self) -> str:
        return "".join(self.parts)


def execute_code(
    code: str,
    namespace: dict[str, Any],
    persist_globals: bool = True,
    *,
    output_limit: int = 1024 * 1024,
) -> dict[str, Any]:
    """Run statements and return the last expression plus bounded output."""
    scope = namespace if persist_globals else namespace.copy()
    scope.pop("result", None)
    scope.setdefault("__name__", "__ida_mcp__")
    stdout, stderr = _Capture(output_limit), _Capture(output_limit)
    start = time.monotonic()
    result: dict[str, Any] = {"result": None}
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            tree = ast.parse(code, filename="<ida-mcp>", mode="exec")
            expression = None
            if tree.body and isinstance(tree.body[-1], ast.Expr):
                expression = ast.Expression(tree.body.pop().value)
            entrypoints = {
                node.name
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name in {"run", "execute", "main"}
            }
            statements = eval(
                compile(
                    tree, "<ida-mcp>", "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
                ),
                scope,
            )
            if inspect.isawaitable(statements):
                asyncio.run(statements)
            if expression is not None:
                result["result"] = eval(
                    compile(
                        expression,
                        "<ida-mcp>",
                        "eval",
                        flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT,
                    ),
                    scope,
                )
            elif entrypoints:
                entrypoint = next(
                    n for n in ("run", "execute", "main") if n in entrypoints
                )
                result["result"] = scope[entrypoint](scope.get("db"))
            elif "result" in scope:
                result["result"] = scope.pop("result")
            if inspect.isawaitable(result["result"]):
                result["result"] = asyncio.run(result["result"])
        except BaseException as error:  # noqa: BLE001
            result["error"] = {
                "type": type(error).__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
            }
    result.update(
        stdout=stdout.getvalue(),
        stderr=stderr.getvalue(),
        elapsed=time.monotonic() - start,
        output_truncated=stdout.truncated or stderr.truncated,
    )
    return result
