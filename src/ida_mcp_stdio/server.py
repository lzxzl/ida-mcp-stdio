"""MCP server using stdio transport and idalib."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .tools import get_registry

logger = logging.getLogger("ida-mcp-stdio")

# TRACE level for detailed request/response logging
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

def trace(self, message, *args, **kwargs):
    """Log at TRACE level (more detailed than DEBUG)."""
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)

logging.Logger.trace = trace

# JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ida-mcp-stdio"
SERVER_VERSION = "0.1.0"

# 结果大小限制
MAX_RESULT_SIZE = 10 * 1024 * 1024  # 10MB


class StdioMCPServer:
    """MCP server communicating over stdio with idalib backend."""

    def __init__(self, binary_path: Optional[Path] = None):
        self.binary_path = binary_path
        self.registry = get_registry()
        self._initialized = False
        self._ida_loaded = False
        self._request_count = 0
        self._error_count = 0
        self._start_time = time.monotonic()

    def initialize_ida(self) -> bool:
        """Initialize idalib and open the binary database.

        Returns:
            True if successful, False otherwise.
        """
        if self._ida_loaded:
            return True

        if self.binary_path is None:
            logger.warning("No binary path specified, idalib not initialized")
            return False

        try:
            # 重定向 IDA 的 stdout 输出到 stderr，避免污染 JSON-RPC 通信
            import io
            original_stdout = sys.stdout
            sys.stdout = sys.stderr
            
            import idapro
            
            # 恢复 stdout
            sys.stdout = original_stdout

            logger.info("Opening database: %s", self.binary_path)
            # Check if database files exist (.idb, .i64, or .id0/.id1/.id2)
            db_path = Path(self.binary_path)
            has_existing_db = (
                db_path.with_suffix('.idb').exists() or
                db_path.with_suffix('.i64').exists() or
                Path(str(db_path) + '.idb').exists() or
                Path(str(db_path) + '.i64').exists() or
                Path(str(db_path) + '.id0').exists()
            )
            
            # 重定向 stdout 到 stderr 以避免 IDA 输出污染 JSON-RPC
            sys.stdout = sys.stderr
            
            if has_existing_db:
                logger.debug("Found existing database files, opening in read mode")
                idapro.open_database(str(self.binary_path), False)  # False = open existing
            else:
                logger.debug("No existing database, creating new one")
                idapro.open_database(str(self.binary_path), True)  # True = create new
            
            self._ida_loaded = True
            logger.info("Database opened successfully")
            
            # Wait for auto-analysis to complete
            try:
                import ida_auto
                logger.info("Waiting for auto-analysis to complete...")
                ida_auto.auto_wait()
                logger.info("Auto-analysis completed")
            except Exception as e:
                logger.warning("Could not wait for auto-analysis: %s", e)
            
            # 恢复 stdout
            sys.stdout = original_stdout
            
            return True
        except ImportError:
            logger.error("idapro module not available - idalib not installed")
            return False
        except Exception as e:
            logger.error("Failed to open database: %s", e)
            return False

    def handle_request(self, request: dict) -> Optional[dict]:
        """Handle a single JSON-RPC request.

        Args:
            request: Parsed JSON-RPC request dict.

        Returns:
            JSON-RPC response dict, or None for notifications.
        """
        self._request_count += 1
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # 验证 JSON-RPC 版本
        if request.get("jsonrpc") != "2.0":
            logger.warning("Invalid JSON-RPC version: %s", request.get("jsonrpc"))

        if not method:
            self._error_count += 1
            return self._error_response(req_id, INVALID_REQUEST, "Missing method")

        if not isinstance(method, str):
            self._error_count += 1
            return self._error_response(req_id, INVALID_REQUEST, "Method must be a string")

        if params is not None and not isinstance(params, dict):
            self._error_count += 1
            return self._error_response(req_id, INVALID_PARAMS, "Params must be an object")

        logger.debug("Request #%d: method=%s id=%s", self._request_count, method, req_id)
        
        # TRACE level: log full request
        logger.trace("Request #%d full content: %s", self._request_count, 
                    json.dumps(request, ensure_ascii=False, indent=2))

        try:
            if method == "initialize":
                response = self._handle_initialize(req_id, params)
            elif method == "notifications/initialized":
                response = None
            elif method == "tools/list":
                response = self._handle_tools_list(req_id)
            elif method == "tools/call":
                response = self._handle_tools_call(req_id, params)
            elif method == "ping":
                response = self._success_response(req_id, {})
            else:
                self._error_count += 1
                response = self._error_response(
                    req_id, METHOD_NOT_FOUND, f"Method not found: {method}"
                )
            
            # TRACE level: log full response
            if response is not None:
                logger.trace("Response #%d full content: %s", self._request_count,
                           json.dumps(response, ensure_ascii=False, indent=2))
            
            return response
        except Exception as e:
            self._error_count += 1
            logger.error("Internal error handling %s: %s", method, traceback.format_exc())
            return self._error_response(req_id, INTERNAL_ERROR, str(e))

    def _handle_initialize(self, req_id: Any, params: dict) -> dict:
        """Handle MCP initialize request."""
        self._initialized = True
        client_info = params.get("clientInfo", {})
        logger.info(
            "Client connected: %s %s",
            client_info.get("name", "unknown"),
            client_info.get("version", ""),
        )
        return self._success_response(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        })

    def _handle_tools_list(self, req_id: Any) -> dict:
        """Handle MCP tools/list request."""
        tools = []
        for tool_def in self.registry.list_tools():
            tools.append({
                "name": tool_def.name,
                "description": tool_def.description,
                "inputSchema": tool_def.input_schema,
            })
        logger.debug("Listed %d tools", len(tools))
        return self._success_response(req_id, {"tools": tools})

    def _handle_tools_call(self, req_id: Any, params: dict) -> dict:
        """Handle MCP tools/call request."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if not tool_name:
            self._error_count += 1
            return self._error_response(req_id, INVALID_PARAMS, "Missing tool name")

        if not isinstance(tool_name, str):
            self._error_count += 1
            return self._error_response(req_id, INVALID_PARAMS, "Tool name must be a string")

        if not isinstance(arguments, dict):
            self._error_count += 1
            return self._error_response(req_id, INVALID_PARAMS, "Arguments must be an object")

        tool_def = self.registry.get_tool(tool_name)
        if tool_def is None:
            self._error_count += 1
            return self._error_response(
                req_id, METHOD_NOT_FOUND, f"Tool not found: {tool_name}"
            )

        start_time = time.monotonic()
        try:
            logger.info("Calling tool: %s(%s)", tool_name, arguments)
            result = tool_def.func(**arguments)
            result_text = json.dumps(result, ensure_ascii=False, default=str)

            # 检查结果大小
            if len(result_text) > MAX_RESULT_SIZE:
                logger.warning(
                    "Tool %s result truncated: %d bytes > %d limit",
                    tool_name, len(result_text), MAX_RESULT_SIZE,
                )
                result_text = json.dumps({
                    "error": f"Result too large ({len(result_text)} bytes), "
                             f"max {MAX_RESULT_SIZE} bytes. Use pagination to reduce result size.",
                    "truncated": True,
                })
                elapsed = time.monotonic() - start_time
                logger.info("Tool %s completed with truncation in %.3fs", tool_name, elapsed)
                return self._success_response(req_id, {
                    "content": [{"type": "text", "text": result_text}],
                    "isError": True,
                })

            elapsed = time.monotonic() - start_time
            logger.info("Tool %s completed in %.3fs", tool_name, elapsed)
            return self._success_response(req_id, {
                "content": [{"type": "text", "text": result_text}],
                "isError": False,
            })
        except TypeError as e:
            # 参数类型或数量错误
            self._error_count += 1
            logger.error("Tool %s parameter error: %s", tool_name, e)
            return self._error_response(
                req_id, INVALID_PARAMS,
                f"Invalid parameters for tool '{tool_name}': {e}"
            )
        except Exception as e:
            self._error_count += 1
            elapsed = time.monotonic() - start_time
            logger.error(
                "Tool %s error after %.3fs: %s", tool_name, elapsed, traceback.format_exc()
            )
            return self._success_response(req_id, {
                "content": [{"type": "text", "text": json.dumps({"error": str(e)})}],
                "isError": True,
            })

    def _success_response(self, req_id: Any, result: Any) -> dict:
        """Create a JSON-RPC success response."""
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _error_response(self, req_id: Any, code: int, message: str) -> dict:
        """Create a JSON-RPC error response."""
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }

    def run(self):
        """Main loop: read from stdin, write to stdout."""
        # 保存原始 stdout 用于 JSON-RPC 通信
        self._original_stdout = sys.stdout
        
        logger.info("Server started, waiting for requests...")

        # 注册信号处理以实现优雅退出
        def _handle_signal(signum, frame):
            logger.info("Received signal %d, shutting down...", signum)
            self._shutdown()
            sys.exit(0)

        signal.signal(signal.SIGTERM, _handle_signal)

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue

                try:
                    request = json.loads(line)
                except json.JSONDecodeError as e:
                    self._error_count += 1
                    logger.warning("JSON parse error: %s (input: %s)", e, line[:200])
                    response = self._error_response(None, PARSE_ERROR, f"Parse error: {e}")
                    self._write_response(response)
                    continue

                if not isinstance(request, dict):
                    self._error_count += 1
                    response = self._error_response(
                        None, INVALID_REQUEST, "Request must be a JSON object"
                    )
                    self._write_response(response)
                    continue

                response = self.handle_request(request)
                if response is not None:
                    self._write_response(response)
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except BrokenPipeError:
            logger.info("Client disconnected (broken pipe)")
        except Exception as e:
            logger.error("Unexpected error in main loop: %s", traceback.format_exc())

        self._shutdown()

    def _shutdown(self):
        """Perform graceful shutdown with statistics."""
        elapsed = time.monotonic() - self._start_time
        logger.info(
            "Server shutting down. Stats: requests=%d, errors=%d, uptime=%.1fs",
            self._request_count, self._error_count, elapsed,
        )

    def _write_response(self, response: dict):
        """Write a JSON-RPC response to stdout."""
        try:
            # 确保使用原始 stdout
            output = self._original_stdout if hasattr(self, '_original_stdout') else sys.stdout
            output.write(json.dumps(response, ensure_ascii=False) + "\n")
            output.flush()
        except (BrokenPipeError, OSError) as e:
            logger.error("Failed to write response: %s", e)


def main():
    """CLI entry point for ida-mcp-server."""
    parser = argparse.ArgumentParser(
        description="IDA Pro MCP server (stdio transport)"
    )
    parser.add_argument(
        "binary",
        nargs="?",
        default=None,
        help="Path to binary file to analyze",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)",
    )
    parser.add_argument(
        "--log-level",
        choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Set log level (overrides --verbose)",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Log file path (default: logs/ida-mcp-YYYYMMDD-HHMMSS.log for TRACE level)",
    )
    args = parser.parse_args()

    # 配置日志系统
    if args.log_level:
        if args.log_level == "TRACE":
            log_level = TRACE
        else:
            log_level = getattr(logging, args.log_level)
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    # 创建日志格式
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # 配置 stderr 日志（始终启用）
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(log_level)
    stderr_handler.setFormatter(logging.Formatter(log_format, date_format))

    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(min(log_level, TRACE))  # 设置为最低级别以捕获所有日志
    root_logger.addHandler(stderr_handler)

    # 如果是 TRACE 级别或指定了日志文件，添加文件处理器
    if log_level == TRACE or args.log_file:
        # 创建 logs 目录
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)

        # 生成日志文件名
        if args.log_file:
            log_file = Path(args.log_file)
        else:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            log_file = log_dir / f"ida-mcp-{timestamp}.log"

        # 创建文件处理器
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(TRACE)  # 文件记录所有 TRACE 级别日志
        file_handler.setFormatter(logging.Formatter(log_format, date_format))
        root_logger.addHandler(file_handler)

        logger.info("TRACE logging enabled, writing to: %s", log_file)

    binary_path = Path(args.binary) if args.binary else None
    if binary_path and not binary_path.exists():
        logger.error("Binary file not found: %s", binary_path)
        sys.exit(1)

    # 自动检测 IDADIR
    _auto_detect_idadir()

    # Import tool modules to trigger registration
    _import_tools()

    server = StdioMCPServer(binary_path=binary_path)

    if binary_path:
        if not server.initialize_ida():
            logger.error("Failed to initialize IDA, exiting")
            sys.exit(1)

    server.run()


def _auto_detect_idadir():
    """Auto-detect IDA Pro installation and set IDADIR if not already set."""
    if os.environ.get("IDADIR"):
        logger.debug("IDADIR already set: %s", os.environ["IDADIR"])
        return

    import platform

    candidates = []
    system = platform.system()

    if system == "Darwin":
        # macOS: /Applications/IDA *.app/Contents/MacOS
        applications = Path("/Applications")
        if applications.exists():
            for app in sorted(applications.glob("IDA*.app"), reverse=True):
                macos_dir = app / "Contents" / "MacOS"
                if (macos_dir / "libidalib.dylib").exists():
                    candidates.append(str(macos_dir))
    elif system == "Linux":
        # Linux: /opt/idapro, /opt/ida, ~/idapro
        for base in ["/opt/idapro", "/opt/ida", Path.home() / "idapro", Path.home() / "ida"]:
            p = Path(base)
            if (p / "libidalib.so").exists() or (p / "idat64").exists():
                candidates.append(str(p))
    elif system == "Windows":
        # Windows: Program Files
        for pf in [os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", "")]:
            if not pf:
                continue
            pf_path = Path(pf)
            if pf_path.exists():
                for d in sorted(pf_path.glob("IDA*"), reverse=True):
                    if (d / "idalib.dll").exists() or (d / "idat64.exe").exists():
                        candidates.append(str(d))

    if candidates:
        idadir = candidates[0]
        os.environ["IDADIR"] = idadir
        logger.info("Auto-detected IDADIR: %s", idadir)
    else:
        logger.debug("Could not auto-detect IDA installation directory")


def _import_tools():
    """Import tool modules to trigger registration via @register_tool."""
    modules = ["analysis", "memory", "types"]
    for mod_name in modules:
        try:
            __import__(f"ida_mcp_stdio.tools.{mod_name}", fromlist=[mod_name])
            logger.debug("Loaded tool module: %s", mod_name)
        except ImportError as e:
            logger.debug("Could not import %s tools: %s", mod_name, e)
