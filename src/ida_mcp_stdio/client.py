"""Python client for the IDA MCP stdio server."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

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
    pass


class IDAMCPClient:
    """Python client that communicates with the MCP server over stdio.

    Usage:
        with IDAMCPClient("binary.exe") as client:
            funcs = client.list_funcs()
            code = client.decompile("main")
    """

    def __init__(
        self,
        binary_path: str | Path,
        server_script: Optional[str] = None,
        verbose: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        """Initialize client and start the server process.

        Args:
            binary_path: Path to binary file to analyze.
            server_script: Custom path to server script. If None, uses
                           'ida-mcp-server' or 'python -m ida_mcp_stdio'.
            verbose: Enable verbose server logging.
            timeout: Default request timeout in seconds.
        """
        self.binary_path = str(binary_path)
        self.timeout = timeout
        self._request_id = 0
        self._process: Optional[subprocess.Popen] = None

        cmd = self._build_command(server_script, verbose)
        try:
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if not verbose else None,
                text=True,
                bufsize=1,  # Line buffered
            )
        except FileNotFoundError as e:
            raise MCPConnectionError(f"Server executable not found: {e}")
        except OSError as e:
            raise MCPConnectionError(f"Failed to start server process: {e}")

    def _build_command(self, server_script: Optional[str], verbose: bool) -> list[str]:
        """Build the command to start the server process."""
        if server_script:
            cmd = [sys.executable, server_script, self.binary_path]
        else:
            cmd = [sys.executable, "-m", "ida_mcp_stdio", self.binary_path]

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
        if self._process is None or self._process.stderr is None:
            return ""
        try:
            # Non-blocking read of available stderr
            import select
            if select.select([self._process.stderr], [], [], 0.1)[0]:
                return self._process.stderr.read(4096)
        except Exception:
            pass
        return ""

    def _send_request(
        self,
        method: str,
        params: Optional[dict] = None,
        timeout: Optional[float] = None,
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
        logger.trace("Sending request: %s", json.dumps(request, ensure_ascii=False, indent=2))
        
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
        response_line = self._read_with_timeout(effective_timeout)

        if not response_line:
            stderr_info = self._get_server_stderr()
            raise MCPConnectionError(
                "Server closed connection unexpectedly"
                + (f"\nServer stderr: {stderr_info}" if stderr_info else "")
            )

        try:
            response = json.loads(response_line)
        except json.JSONDecodeError as e:
            raise MCPConnectionError(f"Invalid JSON response: {e}\nRaw: {response_line[:500]}")

        # TRACE level: log full response
        logger.trace("Received response: %s", json.dumps(response, ensure_ascii=False, indent=2))

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
        result = [None]
        error = [None]

        def _read():
            try:
                # Keep reading until we get a valid JSON-RPC line
                # (skip non-JSON lines like IDA plugin messages)
                while True:
                    line = self._process.stdout.readline()
                    if not line:
                        result[0] = ""
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Check if it looks like JSON-RPC (starts with '{')
                    if line.startswith('{'):
                        result[0] = line
                        break
                    
                    # Skip non-JSON lines (like IDA plugin messages)
                    logger.debug("Skipping non-JSON line: %s", line[:100])
                    
            except Exception as e:
                error[0] = e

        thread = threading.Thread(target=_read, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            raise TimeoutError(f"Request timed out after {timeout}s")

        if error[0] is not None:
            raise MCPConnectionError(f"Failed to read response: {error[0]}")

        return result[0] or ""

    def _send_notification(self, method: str, params: Optional[dict] = None) -> None:
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
        result = self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "ida-mcp-python-client",
                "version": "0.1.0",
            },
        })
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
        arguments: Optional[dict] = None,
        timeout: Optional[float] = None,
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
        result = self._send_request("tools/call", {
            "name": name,
            "arguments": arguments or {},
        }, timeout=timeout)

        # Parse MCP tool result
        content = result.get("content", [])
        is_error = result.get("isError", False)

        if content and content[0].get("type") == "text":
            text = content[0]["text"]
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = text

            if is_error:
                error_msg = parsed.get("error", text) if isinstance(parsed, dict) else text
                raise MCPToolError(name, str(error_msg))
            return parsed

        return content

    # Convenience methods

    def decompile(self, addr: str) -> dict:
        """Decompile a function at the given address.

        Args:
            addr: Function address or name.

        Returns:
            Dict with 'addr' and 'code' keys.
        """
        return self.call_tool("decompile", {"addr": addr})

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
        return self.call_tool("list_funcs", {
            "filter": filter,
            "offset": offset,
            "count": count,
        })

    def disasm(self, addr: str, max_instructions: int = 50) -> dict:
        """Disassemble instructions at the given address.

        Args:
            addr: Start address or function name.
            max_instructions: Maximum number of instructions.

        Returns:
            Dict with disassembly result.
        """
        return self.call_tool("disasm", {
            "addr": addr,
            "max_instructions": max_instructions,
        })

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
        return self.call_tool("find_bytes", {
            "patterns": patterns, "limit": limit, "offset": offset,
        })

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
        return self.call_tool("list_globals", {
            "filter": filter, "offset": offset, "count": count,
        })

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

    def search_structs(self, filter: str) -> list:
        """搜索结构体定义。

        Args:
            filter: 大小写不敏感的结构体名称子串。

        Returns:
            匹配的结构体列表。
        """
        return self.call_tool("search_structs", {"filter": filter})

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
                self._process.stdin.close()
            except (BrokenPipeError, OSError):
                pass

            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

            self._process = None

    def __enter__(self) -> IDAMCPClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
