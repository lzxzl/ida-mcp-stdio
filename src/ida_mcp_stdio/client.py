"""Python client for the IDA MCP stdio server."""

from __future__ import annotations

import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, TypeVar

from . import __version__
from .structured_facts import (
    normalize_batch_search_decompiled_patterns_result,
    normalize_extract_accesses_result,
    normalize_extract_carrier_facts_result,
    normalize_extract_function_facts_result,
    normalize_extract_lock_regions_result,
    normalize_extract_size_flow_facts_result,
    normalize_list_callsites_result,
)

logger = logging.getLogger("ida-mcp-stdio.client")

# TRACE level for detailed request/response logging
TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def trace(self, message, *args, **kwargs):
    """Log at TRACE level (more detailed than DEBUG)."""
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)


logging.Logger.trace = trace

# 默认请求超时（秒）
DEFAULT_TIMEOUT = 300

_READER_EOF = object()
_ClientT = TypeVar("_ClientT", bound="IDAMCPClient")


class MCPError(Exception):
    """MCP 协议级错误。"""

    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"MCP error [{code}]: {message}")


class MCPToolError(Exception):
    """MCP 工具执行错误。"""

    def __init__(self, tool_name: str, message: str):
        self.tool_name = tool_name
        self.message = message
        super().__init__(f"Tool '{tool_name}' error: {message}")


class MCPConnectionError(Exception):
    """MCP 连接错误（服务器进程崩溃或通信失败）。"""


class IDAMCPClient:
    """Python client that communicates with the MCP server over stdio.

    Usage:
        with IDAMCPClient("binary.exe") as client:
            funcs = client.list_funcs()
            code = client.decompile("main")
    """

    def __init__(
        self,
        binary_path: str | Path | None = None,
        server_script: str | None = None,
        verbose: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        server_command: str | list[str] | None = None,
        server_args: list[str] | None = None,
        process_env: dict[str, Any] | None = None,
        tool_profile: str = "legacy",
    ):
        """Initialize client and start the server process.

        Args:
            binary_path: Path to binary file to analyze (optional).
                        If None, use open_database tool to load binaries.
            server_script: Custom path to server script. If None, uses
                           'ida-mcp-server' or 'python -m ida_mcp_stdio'.
            verbose: Enable verbose server logging.
            timeout: Default request timeout in seconds.
            server_command: Optional explicit executable/argv prefix used to
                            start the MCP stdio server.
            server_args: Optional arguments appended after server_command.
            process_env: Optional extra environment variables for the server
                         process.
        """
        self.binary_path = str(binary_path) if binary_path else None
        self.timeout = timeout
        self.tool_profile = tool_profile
        self._request_id = 0
        self._request_lock = threading.Lock()
        self._process: subprocess.Popen | None = None
        self._response_queue: queue.Queue[object] = queue.Queue()
        self._stdout_reader_thread: threading.Thread | None = None
        self._stderr_reader_thread: threading.Thread | None = None
        self._stderr_tail: deque[str] = deque(maxlen=200)
        self._stderr_tail_lock = threading.Lock()

        cmd = self._build_command(server_script, verbose, server_command, server_args)
        popen_env = os.environ.copy()
        if not server_command and not server_script:
            source_root = str(Path(__file__).resolve().parent.parent)
            popen_env["PYTHONPATH"] = os.pathsep.join(
                filter(None, (source_root, popen_env.get("PYTHONPATH", "")))
            )
        if process_env:
            popen_env.update(
                {
                    str(key): str(value)
                    for key, value in process_env.items()
                    if value is not None
                }
            )
        try:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if not verbose else None,
                text=True,
                bufsize=1,  # Line buffered
                env=popen_env,
            )
        except FileNotFoundError as e:
            raise MCPConnectionError(f"Server executable not found: {e}")
        except OSError as e:
            raise MCPConnectionError(f"Failed to start server process: {e}")

        self._start_stdout_reader()
        self._start_stderr_reader()

    def _build_command(
        self,
        server_script: str | None,
        verbose: bool,
        server_command: str | list[str] | None,
        server_args: list[str] | None,
    ) -> list[str]:
        """Build the command to start the server process."""
        if server_command:
            if isinstance(server_command, (list, tuple)):
                cmd = [str(part) for part in server_command if str(part).strip()]
            else:
                token = str(server_command).strip()
                cmd = [token] if token else []
            cmd.extend(str(arg) for arg in (server_args or []) if str(arg).strip())
            if self.binary_path:
                cmd.append(self.binary_path)
        elif server_script:
            cmd = [sys.executable, server_script]
            if self.binary_path:
                cmd.append(self.binary_path)
        else:
            cmd = [
                sys.executable,
                "-m",
                "ida_mcp_stdio",
                "--tool-profile",
                self.tool_profile,
            ]
            cmd.extend(server_args or [])
            if self.binary_path:
                cmd.append(self.binary_path)

        if verbose:
            cmd.append("--verbose")
        return cmd

    def _next_id(self) -> int:
        """Get the next request ID."""
        self._request_id += 1
        return self._request_id

    @property
    def is_running(self) -> bool:
        """Check if the server process is still running."""
        return self._process is not None and self._process.poll() is None

    def _get_server_stderr(self) -> str:
        """Try to read stderr output from the server for error diagnostics."""
        with self._stderr_tail_lock:
            return "".join(self._stderr_tail)[-4096:]

    def _start_stdout_reader(self) -> None:
        """Start a single background reader for server stdout."""
        if self._process is None or self._process.stdout is None:
            return
        if self._stdout_reader_thread is not None:
            return

        def _reader() -> None:
            try:
                while True:
                    line = self._process.stdout.readline()
                    if not line:
                        self._response_queue.put(_READER_EOF)
                        break

                    line = line.strip()
                    if not line:
                        continue

                    if line.startswith("{"):
                        self._response_queue.put(line)
                        continue

                    logger.debug("Skipping non-JSON line: %s", line[:100])
            except Exception as e:  # noqa: BLE001
                self._response_queue.put(e)

        self._stdout_reader_thread = threading.Thread(
            target=_reader,
            name="ida-mcp-stdout-reader",
            daemon=True,
        )
        self._stdout_reader_thread.start()

    def _start_stderr_reader(self) -> None:
        """Continuously drain server stderr so logging cannot block the child."""
        if self._process is None or self._process.stderr is None:
            return
        if self._stderr_reader_thread is not None:
            return

        def _reader() -> None:
            try:
                while True:
                    line = self._process.stderr.readline()
                    if not line:
                        break
                    if len(line) > 4096:
                        line = line[:4096] + "...[truncated]\n"
                    with self._stderr_tail_lock:
                        self._stderr_tail.append(line)
                    logger.debug("Server stderr: %s", line.rstrip()[:500])
            except Exception as e:  # noqa: BLE001
                logger.debug("stderr reader stopped: %s", e)

        self._stderr_reader_thread = threading.Thread(
            target=_reader,
            name="ida-mcp-stderr-reader",
            daemon=True,
        )
        self._stderr_reader_thread.start()

    def _send_request(
        self,
        method: str,
        params: dict | None = None,
        timeout: float | None = None,
    ) -> Any:
        with self._request_lock:
            return self._send_request_locked(method, params, timeout)

    def _send_request_locked(
        self, method: str, params: dict | None, timeout: float | None
    ) -> Any:
        """Send a JSON-RPC request and return the result.

        Args:
            method: JSON-RPC method name.
            params: Method parameters.
            timeout: Request timeout in seconds (overrides default).

        Returns:
            The result field from the response.

        Raises:
            MCPConnectionError: If communication with server fails.
            MCPError: If the server returns a protocol-level error.
            TimeoutError: If the request times out.
        """
        if not self.is_running:
            exit_code = self._process.returncode if self._process else None
            raise MCPConnectionError(
                f"Server process is not running (exit code: {exit_code})"
            )

        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._next_id(),
        }

        request_line = json.dumps(request, ensure_ascii=False) + "\n"

        # TRACE level: log full request
        logger.trace(
            "Sending request: %s", json.dumps(request, ensure_ascii=False, indent=2)
        )

        try:
            self._process.stdin.write(request_line)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            stderr_info = self._get_server_stderr()
            raise MCPConnectionError(
                f"Failed to send request: {e}"
                + (f"\nServer stderr: {stderr_info}" if stderr_info else "")
            )

        # 使用超时读取响应
        effective_timeout = timeout if timeout is not None else self.timeout
        deadline = time.monotonic() + effective_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Request timed out after {effective_timeout}s")
            response_line = self._read_with_timeout(remaining)
            if not response_line:
                break
            try:
                response = json.loads(response_line)
            except json.JSONDecodeError as error:
                raise MCPConnectionError(f"Invalid JSON response: {error}") from error
            if not isinstance(response, dict):
                raise MCPConnectionError("Response must be a JSON object")
            if "method" in response and "id" not in response:
                continue
            if response.get("id") != request["id"]:
                logger.debug(
                    "Skipping stale response id=%s, expected=%s",
                    response.get("id"),
                    request["id"],
                )
                continue
            break

        if not response_line:
            stderr_info = self._get_server_stderr()
            raise MCPConnectionError(
                "Server closed connection unexpectedly"
                + (f"\nServer stderr: {stderr_info}" if stderr_info else "")
            )

        try:
            response = json.loads(response_line)
        except json.JSONDecodeError as e:
            raise MCPConnectionError(
                f"Invalid JSON response: {e}\nRaw: {response_line[:500]}"
            )

        # TRACE level: log full response
        logger.trace(
            "Received response: %s", json.dumps(response, ensure_ascii=False, indent=2)
        )

        if "error" in response:
            error = response["error"]
            raise MCPError(
                code=error.get("code", -1),
                message=error.get("message", "Unknown error"),
            )

        return response.get("result", {})

    def _read_with_timeout(self, timeout: float) -> str:
        """Read a line from stdout with timeout.

        Args:
            timeout: Timeout in seconds.

        Returns:
            The line read, or empty string if no data.

        Raises:
            TimeoutError: If the read times out.
        """
        try:
            item = self._response_queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"Request timed out after {timeout}s")

        if item is _READER_EOF:
            return ""

        if isinstance(item, Exception):
            raise MCPConnectionError(f"Failed to read response: {item}")

        return str(item)

    def _send_notification(self, method: str, params: dict | None = None) -> None:
        """Send a JSON-RPC notification (no response expected).

        Args:
            method: JSON-RPC method name.
            params: Method parameters.

        Raises:
            MCPConnectionError: If communication with server fails.
        """
        if not self.is_running:
            raise MCPConnectionError("Server process is not running")

        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }

        notification_line = json.dumps(notification, ensure_ascii=False) + "\n"
        try:
            self._process.stdin.write(notification_line)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise MCPConnectionError(f"Failed to send notification: {e}")

    # MCP protocol methods

    def initialize(self) -> dict:
        """Initialize the MCP connection.

        Returns:
            Server capabilities dict.
        """
        result = self._send_request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {
                    "name": "ida-mcp-python-client",
                    "version": __version__,
                },
            },
        )
        # Send initialized notification
        self._send_notification("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        """List available tools.

        Returns:
            List of tool definitions.
        """
        result = self._send_request("tools/list")
        return result.get("tools", [])

    def call_tool(
        self,
        name: str,
        arguments: dict | None = None,
        timeout: float | None = None,
    ) -> Any:
        """Call a tool by name.

        Args:
            name: Tool name.
            arguments: Tool arguments.
            timeout: Override timeout for this call.

        Returns:
            Tool result (parsed from JSON content).

        Raises:
            MCPToolError: If the tool execution fails.
            MCPError: If a protocol-level error occurs.
            MCPConnectionError: If communication fails.
            TimeoutError: If the request times out.
        """
        result = self._send_request(
            "tools/call",
            {
                "name": name,
                "arguments": arguments or {},
            },
            timeout=timeout,
        )

        # Parse MCP tool result
        content = result.get("content", [])
        is_error = result.get("isError", False)

        if "structuredContent" in result:
            parsed = result["structuredContent"]
            if is_error:
                raise MCPToolError(name, str(parsed.get("error", parsed)))
            return self._resolve_artifact(parsed)

        if content and content[0].get("type") == "text":
            text = content[0]["text"]
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = text

            if is_error:
                error_msg = (
                    parsed.get("error", text) if isinstance(parsed, dict) else text
                )
                raise MCPToolError(name, str(error_msg))
            return self._resolve_artifact(parsed)

        if is_error:
            raise MCPToolError(name, str(content or "Tool failed"))
        return content

    def _resolve_artifact(self, value: Any) -> Any:
        if not isinstance(value, dict) or "artifact" not in value:
            return value
        uri = value["artifact"].get("uri")
        if not uri:
            return value
        chunks = []
        while uri:
            page = json.loads(self.read_resource(uri)["contents"][0]["text"])
            chunks.append(page["chunk"])
            uri = page["next_uri"]
        return json.loads("".join(chunks))

    def read_resource(self, uri: str) -> dict:
        """Read a page of an artifact belonging to the connected session."""
        return self._send_request("resources/read", {"uri": uri})

    def execute_python(
        self,
        code: str,
        instance_id: str | None = None,
        timeout: float = 360,
        persist_globals: bool = True,
    ) -> dict:
        """Run code in a database worker and return its result/output."""
        return self.call_tool(
            "execute_python",
            {
                "code": code,
                "instance_id": instance_id,
                "timeout": timeout,
                "persist_globals": persist_globals,
            },
            timeout=timeout + 10,
        )

    def reference(self, query: str, **options) -> dict:
        """Search installed API/helper documentation without opening IDA."""
        return self.call_tool("reference", {"query": query, **options})

    def open_database(self, path: str | Path, set_current: bool = True) -> dict:
        """Attach another database without closing existing targets."""
        return self.call_tool(
            "open_database",
            {"path": str(path), "set_current": set_current},
            timeout=370,
        )

    def list_databases(self) -> dict:
        return self.call_tool("list_databases")

    def save_database(self, instance_id: str | None = None) -> dict:
        return self.call_tool("save_database", {"instance_id": instance_id})

    def close_database(self, instance_id: str | None = None, save: bool = True) -> dict:
        return self.call_tool(
            "close_database", {"instance_id": instance_id, "save": save}
        )

    # Convenience methods

    def decompile(
        self,
        addr: str = "",
        addrs: str | list[str] | None = None,
    ) -> dict | list:
        """Decompile one or more functions.

        Args:
            addr: Single function address or name.
            addrs: Function addresses/names as comma-separated string or list.

        Returns:
            Single-result dict (legacy single mode) or list of result dicts (batch mode).
        """
        arguments: dict = {}
        if addr:
            arguments["addr"] = addr
        if addrs not in (None, "", []):
            arguments["addrs"] = addrs
        return self.call_tool("decompile", arguments)

    def decompile_batch(self, addrs: str | list[str]) -> list:
        """Decompile multiple functions in one request.

        Args:
            addrs: Function addresses/names as comma-separated string or list.

        Returns:
            List of decompilation results.
        """
        return self.call_tool("decompile", {"addrs": addrs})

    def get_function_prototype(self, addr: str) -> dict:
        """基于类型信息获取函数签名（best-effort，类型缺失时可能不完整）。"""
        return self.call_tool("get_function_prototype", {"addr": addr})

    def get_stack_frame(self, addr: str) -> dict:
        """启发式获取函数栈帧布局（可能不完整）。"""
        return self.call_tool("get_stack_frame", {"addr": addr})

    def search_decompiled_code(
        self,
        pattern: str,
        scope: str = "all_functions",
        addrs: str | list[str] | None = None,
        function_filter: str = "",
        max_functions: int = 0,
        max_matches: int = 200,
        case_sensitive: bool = False,
    ) -> dict:
        """在伪代码文本中做正则搜索（非语义分析，受反编译覆盖率影响）。"""
        arguments: dict[str, Any] = {
            "pattern": pattern,
            "scope": scope,
            "function_filter": function_filter,
            "max_functions": max_functions,
            "max_matches": max_matches,
            "case_sensitive": case_sensitive,
        }
        if addrs not in (None, "", []):
            arguments["addrs"] = addrs
        return self.call_tool("search_decompiled_code", arguments)

    def batch_search_decompiled_patterns(
        self,
        patterns: list[dict[str, Any]],
        scope: str = "all_functions",
        addrs: str | list[str] | None = None,
        function_filter: str = "",
        max_functions: int = 0,
        max_matches: int = 1000,
        case_sensitive: bool = False,
    ) -> dict:
        """Planned structured batch pseudocode search with client-side schema normalization."""
        arguments: dict[str, Any] = {
            "patterns": patterns,
            "scope": scope,
            "function_filter": function_filter,
            "max_functions": max_functions,
            "max_matches": max_matches,
            "case_sensitive": case_sensitive,
        }
        if addrs not in (None, "", []):
            arguments["addrs"] = addrs
        result = self.call_tool("batch_search_decompiled_patterns", arguments)
        return normalize_batch_search_decompiled_patterns_result(
            result, patterns=patterns
        )

    def list_callsites(
        self,
        func: str,
        callee_filter: str = "*",
        include_args: bool = True,
        max_calls: int = 0,
    ) -> dict:
        """Planned structured callsite listing with client-side schema normalization."""
        result = self.call_tool(
            "list_callsites",
            {
                "func": func,
                "callee_filter": callee_filter,
                "include_args": include_args,
                "max_calls": max_calls,
            },
        )
        return normalize_list_callsites_result(result)

    def extract_function_facts(
        self,
        func: str,
        filters: dict[str, Any] | None = None,
        include_calls: bool = True,
        include_accesses: bool = True,
        include_invalidations: bool = True,
        include_locks: bool = True,
    ) -> dict:
        """Planned aggregate function fact extraction with client-side schema normalization."""
        result = self.call_tool(
            "extract_function_facts",
            {
                "func": func,
                "filters": filters or {},
                "include_calls": include_calls,
                "include_accesses": include_accesses,
                "include_invalidations": include_invalidations,
                "include_locks": include_locks,
            },
        )
        return normalize_extract_function_facts_result(result)

    def extract_accesses(
        self,
        func: str,
        filters: dict[str, Any] | None = None,
    ) -> dict:
        """Planned generic access extraction with client-side schema normalization."""
        result = self.call_tool(
            "extract_accesses",
            {
                "func": func,
                "filters": filters or {},
            },
        )
        return normalize_extract_accesses_result(result)

    def extract_lock_regions(
        self,
        func: str,
        lock_names: list[str] | str | None = None,
        lock_api_patterns: list[str] | str | None = None,
    ) -> dict:
        """Planned lock region extraction with client-side schema normalization."""
        arguments: dict[str, Any] = {"func": func}
        if lock_names not in (None, "", []):
            arguments["lock_names"] = lock_names
        if lock_api_patterns not in (None, "", []):
            arguments["lock_api_patterns"] = lock_api_patterns
        result = self.call_tool("extract_lock_regions", arguments)
        return normalize_extract_lock_regions_result(result)

    def extract_carrier_facts(
        self,
        func: str,
        filters: dict[str, Any] | None = None,
    ) -> dict:
        """Planned lifecycle carrier aggregation with client-side schema normalization."""
        result = self.call_tool(
            "extract_carrier_facts",
            {
                "func": func,
                "filters": filters or {},
            },
        )
        return normalize_extract_carrier_facts_result(result)

    def extract_size_flow_facts(
        self,
        func: str,
        filters: dict[str, Any] | None = None,
    ) -> dict:
        """Generic size/source/transform/guard/allocation/access fact extraction."""
        result = self.call_tool(
            "extract_size_flow_facts",
            {
                "func": func,
                "filters": filters or {},
            },
        )
        return normalize_extract_size_flow_facts_result(result)

    def extract_hdf_ril_dispatch_microcode_facts(
        self,
        dispatch_funcs: list[str] | str | None = None,
        registration_funcs: list[str] | str | None = None,
        max_functions: int = 16,
    ) -> dict:
        """Best-effort HDF/RIL dispatch raw facts from Hex-Rays microcode."""
        return self.call_tool(
            "extract_hdf_ril_dispatch_microcode_facts",
            {
                "dispatch_funcs": dispatch_funcs or [],
                "registration_funcs": registration_funcs or [],
                "max_functions": int(max_functions or 16),
            },
        )

    def extract_selector_dispatch_microcode_facts(
        self,
        dispatch_funcs: list[str] | str | None = None,
        registration_funcs: list[str] | str | None = None,
        max_functions: int = 16,
        expected_selectors: list[int] | str | None = None,
        selector_min: int | None = None,
        selector_max: int | None = None,
        handler_prefixes: list[str] | str | None = None,
        target_functions: list[str] | str | None = None,
        extractor_profile: str = "generic_selector_dispatch",
        infer_handler_family_from_registration: bool = True,
    ) -> dict:
        """Generic selector-dispatch raw facts from Hex-Rays microcode."""
        payload: dict[str, Any] = {
            "dispatch_funcs": dispatch_funcs or [],
            "registration_funcs": registration_funcs or [],
            "max_functions": int(max_functions or 16),
            "extractor_profile": extractor_profile,
            "infer_handler_family_from_registration": bool(
                infer_handler_family_from_registration
            ),
        }
        if expected_selectors:
            payload["expected_selectors"] = expected_selectors
        if selector_min is not None:
            payload["selector_min"] = selector_min
        if selector_max is not None:
            payload["selector_max"] = selector_max
        if handler_prefixes:
            payload["handler_prefixes"] = handler_prefixes
        if target_functions:
            payload["target_functions"] = target_functions
        return self.call_tool("extract_selector_dispatch_microcode_facts", payload)

    def extract_indirect_callsite_microcode_facts(
        self,
        caller_funcs: list[str] | str | None = None,
        target_functions: list[str] | str | None = None,
        target_method_names: list[str] | str | None = None,
        class_prefixes: list[str] | str | None = None,
        max_functions: int = 16,
        extractor_profile: str = "generic_indirect_callsite",
    ) -> dict:
        """Generic indirect-callsite raw facts from Hex-Rays microcode."""
        return self.call_tool(
            "extract_indirect_callsite_microcode_facts",
            {
                "caller_funcs": caller_funcs or [],
                "target_functions": target_functions or [],
                "target_method_names": target_method_names or [],
                "class_prefixes": class_prefixes or [],
                "max_functions": int(max_functions or 16),
                "extractor_profile": extractor_profile,
            },
        )

    def trace_parameter(
        self,
        func: str,
        param_index: int,
        direction: str = "backward",
        max_depth: int = 3,
        max_callers_per_level: int = 20,
    ) -> dict:
        """启发式参数追踪（非严格 SSA/污点分析，复杂路径可能追不全）。"""
        return self.call_tool(
            "trace_parameter",
            {
                "func": func,
                "param_index": param_index,
                "direction": direction,
                "max_depth": max_depth,
                "max_callers_per_level": max_callers_per_level,
            },
        )

    def get_data_flow(
        self,
        func: str,
        param_index: int,
        direction: str = "backward",
        max_depth: int = 3,
        max_callers_per_level: int = 20,
    ) -> dict:
        """追踪数据流（trace_parameter 别名，继承同样的启发式限制）。"""
        return self.call_tool(
            "get_data_flow",
            {
                "func": func,
                "param_index": param_index,
                "direction": direction,
                "max_depth": max_depth,
                "max_callers_per_level": max_callers_per_level,
            },
        )

    def list_funcs(
        self,
        filter: str = "",
        offset: int = 0,
        count: int = 50,
    ) -> dict:
        """List functions in the binary.

        Args:
            filter: Glob pattern to filter function names.
            offset: Pagination offset.
            count: Number of results.

        Returns:
            Dict with 'data', 'offset', 'count', 'more' keys.
        """
        return self.call_tool(
            "list_funcs",
            {
                "filter": filter,
                "offset": offset,
                "count": count,
            },
        )

    def disasm(self, addr: str, max_instructions: int = 50) -> dict:
        """Disassemble instructions at the given address.

        Args:
            addr: Start address or function name.
            max_instructions: Maximum number of instructions.

        Returns:
            Dict with disassembly result.
        """
        return self.call_tool(
            "disasm",
            {
                "addr": addr,
                "max_instructions": max_instructions,
            },
        )

    def xrefs_to(self, addrs: str, limit: int = 100) -> list:
        """获取指向指定地址的交叉引用。

        Args:
            addrs: 目标地址（逗号分隔或单个地址）。
            limit: 每个地址的最大交叉引用数。

        Returns:
            交叉引用结果列表。
        """
        return self.call_tool("xrefs_to", {"addrs": addrs, "limit": limit})

    def callees(self, addrs: str, limit: int = 200) -> list:
        """获取指定函数调用的其他函数。

        Args:
            addrs: 函数地址（逗号分隔或单个地址）。
            limit: 每个函数的最大被调用数。

        Returns:
            被调用函数结果列表。
        """
        return self.call_tool("callees", {"addrs": addrs, "limit": limit})

    def find_bytes(self, patterns: str, limit: int = 1000, offset: int = 0) -> list:
        """搜索字节模式。

        Args:
            patterns: 字节模式（如 '48 8B ?? ??'），支持通配符。
            limit: 每个模式的最大匹配数。
            offset: 跳过前 N 个匹配。

        Returns:
            匹配结果列表。
        """
        return self.call_tool(
            "find_bytes",
            {
                "patterns": patterns,
                "limit": limit,
                "offset": offset,
            },
        )

    def imports(self, offset: int = 0, count: int = 0) -> dict:
        """获取导入符号列表。

        Args:
            offset: 分页偏移量。
            count: 返回数量（0=全部）。

        Returns:
            导入符号结果字典。
        """
        return self.call_tool("imports", {"offset": offset, "count": count})

    def list_globals(self, filter: str = "", offset: int = 0, count: int = 50) -> dict:
        """获取全局变量列表。

        Args:
            filter: Glob 模式过滤名称。
            offset: 分页偏移量。
            count: 返回数量。

        Returns:
            全局变量结果字典。
        """
        return self.call_tool(
            "list_globals",
            {
                "filter": filter,
                "offset": offset,
                "count": count,
            },
        )

    def get_bytes(self, addr: str, size: int) -> dict:
        """读取指定地址的原始字节。

        Args:
            addr: 读取起始地址。
            size: 读取字节数。

        Returns:
            包含十六进制字节数据的字典。
        """
        return self.call_tool("get_bytes", {"addr": addr, "size": size})

    def get_int(self, addr: str, ty: str) -> dict:
        """读取指定地址的整数值。

        Args:
            addr: 读取地址。
            ty: 整数类型（i8/u8/i16le/i32be 等）。

        Returns:
            包含整数值的字典。
        """
        return self.call_tool("get_int", {"addr": addr, "ty": ty})

    def get_string(self, addrs: str) -> list:
        """读取指定地址的字符串。

        Args:
            addrs: 地址（逗号分隔或单个地址）。

        Returns:
            字符串结果列表。
        """
        return self.call_tool("get_string", {"addrs": addrs})

    def search_structs(
        self,
        filter: str,
        offset: int = 0,
        count: int = 50,
        max_name_chars: int = 512,
    ) -> dict:
        """搜索结构体定义。

        Args:
            filter: 大小写不敏感的结构体名称子串。
            offset: 分页起始偏移。
            count: 最多返回多少个结构体。
            max_name_chars: 单个结构体名称最大字符数。

        Returns:
            包含 data/count/total/more 的分页结构体列表。
        """
        return self.call_tool(
            "search_structs",
            {
                "filter": filter,
                "offset": offset,
                "count": count,
                "max_name_chars": max_name_chars,
            },
        )

    def get_struct_definition(self, struct: str) -> dict:
        """获取结构体类型定义（不读取内存值）。

        Args:
            struct: 结构体名称。

        Returns:
            结构体字段定义字典。
        """
        return self.call_tool("get_struct_definition", {"struct": struct})

    def read_struct(self, addr: str, struct: str = "") -> dict:
        """读取指定地址的结构体字段值。

        Args:
            addr: 内存地址。
            struct: 结构体名称（留空则自动检测）。

        Returns:
            结构体字段值字典。
        """
        return self.call_tool("read_struct", {"addr": addr, "struct": struct})

    def export_funcs(self, addrs: str, format: str = "json") -> list:
        """导出函数信息。

        Args:
            addrs: 函数地址（逗号分隔或单个地址）。
            format: 导出格式（json/c_header/prototypes）。

        Returns:
            函数信息列表。
        """
        return self.call_tool("export_funcs", {"addrs": addrs, "format": format})

    def close(self):
        """Close the connection and terminate the server process."""
        if self._process is not None:
            try:
                if self._process.stdin is not None:
                    self._process.stdin.close()
            except (BrokenPipeError, OSError, ValueError):
                pass

            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

            try:
                if self._process.stdout is not None:
                    self._process.stdout.close()
            except (OSError, ValueError):
                pass

            try:
                if self._process.stderr is not None:
                    self._process.stderr.close()
            except (OSError, ValueError):
                pass

            if self._stdout_reader_thread is not None:
                self._stdout_reader_thread.join(timeout=1)
                self._stdout_reader_thread = None

            if self._stderr_reader_thread is not None:
                self._stderr_reader_thread.join(timeout=1)
                self._stderr_reader_thread = None

            self._process = None

    # Keep the base install compatible with Python 3.10 without typing_extensions.
    def __enter__(self: _ClientT) -> _ClientT:  # noqa: PYI019
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
