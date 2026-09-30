"""MCP server using stdio transport and idalib."""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import queue
import shutil
import signal
import sys
import threading
import time
import traceback
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .session import SessionStore
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
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
COMPACT_TOOLS = {
    "open_database",
    "close_database",
    "list_databases",
    "save_database",
    "execute_python",
    "reference",
}
RUNTIME_TOOLS = COMPACT_TOOLS | {"get_current_database"}
INSTRUCTIONS = (
    "Open databases with open_database, check APIs with reference, then combine "
    "analysis in execute_python. Use instance_id for cross-binary work; globals "
    "persist per database. IDAPython imports and tools analysis helpers are available; "
    "db/ida_domain are available when installed. Filter and summarize before returning. "
    "Python executes with full local user privileges and can change files and IDBs. "
    "Save changes explicitly with save_database. Read artifact pages via resources/read."
)
SERVER_NAME = "ida-mcp-stdio"
SERVER_VERSION = __version__
LOG_LEVELS = {
    name: rank
    for rank, name in enumerate(
        (
            "debug",
            "info",
            "notice",
            "warning",
            "error",
            "critical",
            "alert",
            "emergency",
        )
    )
}

# 结果大小限制
MAX_RESULT_SIZE = 10 * 1024 * 1024  # 10MB
DATABASE_SIDECAR_SUFFIXES = (
    ".i64",
    ".idb",
    ".id0",
    ".id1",
    ".id2",
    ".nam",
    ".til",
)
IDA_DB_SPACE_LOW = "IDA_DB_SPACE_LOW"
IDA_DB_ESTIMATE_MIN_BYTES = 1536 * 1024 * 1024
IDA_DB_REQUIRED_MULTIPLIER = 3
IDA_DB_FALLBACK_BINARY_MULTIPLIER = 4


class StdioMCPServer:
    """MCP server communicating over stdio with idalib backend."""

    def __init__(
        self,
        binary_path: Path | None = None,
        *,
        backend: str = "native",
        tool_profile: str = "compact",
        max_workers: int = 4,
        session_dir: Path | None = None,
        session_log: Path | None = None,
        agent: str = "unknown",
        inline_limit: int = 65536,
        idle_timeout: float | None = None,
    ):
        from .backends import LocalBackend, NexusBackend, normalize_idle_timeout

        if backend not in {"native", "nexus", "embedded"}:
            raise ValueError("backend must be native or nexus")
        if tool_profile not in {"compact", "legacy", "full"}:
            raise ValueError("tool_profile must be compact, legacy or full")
        self.idle_timeout = normalize_idle_timeout(idle_timeout)
        if self.idle_timeout is not None and backend != "nexus":
            raise ValueError("idle_timeout requires the Nexus backend")
        self.backend_name = backend
        self.max_workers = max_workers
        self.tool_profile = tool_profile
        self.session = SessionStore(session_dir, inline_limit, session_log, agent)
        self._write_lock = threading.Lock()
        self._notification_sink = None
        self._logging_level = "warning"
        self._protocol_version = SUPPORTED_PROTOCOLS[-1]
        self._closed = False
        self._request_context = ContextVar("ida_mcp_request", default=None)
        self._active_operations = {}
        self._pending_requests = {}
        self._operations_lock = threading.Lock()
        self.binary_path = binary_path  # Initial binary (for backward compatibility)
        self.current_database_path: Path | None = None  # Currently open database
        self.registry = get_registry()
        self._initialized = False
        self._ida_loaded = False  # True if a database is currently open
        self._idapro_imported = False  # True if idapro module has been imported
        self._idapro = None  # Reference to idapro module
        self._request_count = 0
        self._error_count = 0
        self._start_time = time.monotonic()
        self.manager = (
            None
            if backend == "embedded"
            else (
                NexusBackend(
                    idle_timeout=self.idle_timeout, on_event=self._on_database_event
                )
                if backend == "nexus"
                else LocalBackend(max_workers)
            )
        )

    def set_notification_sink(self, sink) -> None:
        """Bind the transport's thread-safe notification writer for this session."""
        self._notification_sink = sink

    def _session_metadata(self, *sources) -> dict:
        """Accept transcript hints while keeping session and agent identity local."""
        metadata = {}
        aliases = {"claude-code": "claude", "claude-desktop": "claude"}
        agent_key = aliases.get(self.session.agent, self.session.agent)
        for source in sources:
            if not isinstance(source, dict):
                continue
            for key, value in source.items():
                if not isinstance(key, str):
                    continue
                if key.endswith("_session_path"):
                    if key != agent_key + "_session_path":
                        continue
                    if not isinstance(value, str) or not value:
                        continue
                if key not in {"agent", "session_id", "mcp_id"}:
                    metadata[key] = value
        metadata.update(session_id=self.session.session_id, agent=self.session.agent)
        return metadata

    def _on_database_event(self, event: str, fields: dict) -> None:
        """Trace Nexus lifecycle changes and report database loss to the client."""
        fields = dict(fields)
        error = fields.get("error")
        if isinstance(error, BaseException):
            fields["error"] = {"type": type(error).__name__, "message": str(error)}
        self.session.record(event, **fields)
        if event not in {"database_disconnected", "database_release_error"}:
            return
        level = "warning" if event == "database_disconnected" else "error"
        if not self._initialized or LOG_LEVELS[level] < LOG_LEVELS[self._logging_level]:
            return
        sink = self._notification_sink
        if sink is not None:
            try:
                sink(
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/message",
                        "params": {
                            "level": level,
                            "logger": "ida-mcp.database",
                            "data": {
                                "event": event,
                                **fields,
                                "hint": "Reopen the database before continuing; unsaved changes may be lost.",
                            },
                        },
                    }
                )
            except Exception:
                logger.exception("Could not send database lifecycle notification")

    def operation_id(self) -> str | None:
        context = self._request_context.get()
        return context[1] if context else None

    def track_operation(self, target: str) -> None:
        context = self._request_context.get()
        if context:
            with self._operations_lock:
                if self._pending_requests[context[0]].is_set():
                    raise RuntimeError("Operation cancelled before execution")
                self._active_operations[context[0]] = (target, context[1])

    def prepare_request(self, request_id):
        with self._operations_lock:
            return self._pending_requests.setdefault(request_id, threading.Event())

    def cancel_event(self):
        context = self._request_context.get()
        return self.prepare_request(context[0]) if context else None

    def cancel_request(self, request_id) -> None:
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            return
        with self._operations_lock:
            pending = self._pending_requests.get(request_id)
            if pending:
                pending.set()
            operation = self._active_operations.get(request_id)
        if operation and self.manager:
            self.manager.cancel_operation(*operation)
            self.session.record(
                "tool_cancel", request_id=request_id, instance_id=operation[0]
            )

    def initialize_ida(self) -> bool:
        """Initialize idalib and open the binary database (legacy method for backward compatibility).

        Returns:
            True if successful, False otherwise.
        """
        if self._ida_loaded:
            return True

        if self.binary_path is None:
            logger.warning("No binary path specified, idalib not initialized")
            return False

        if self.manager is not None:
            try:
                return self.manager.open_database(str(self.binary_path)).get(
                    "success", False
                )
            except (RuntimeError, ValueError, OSError) as error:
                logger.error("Could not initialize database: %s", error)
                return False

        # Use new internal method
        result = self._open_database_internal(self.binary_path, force_reanalyze=False)
        return result.get("success", False)

    def _import_idapro(self) -> bool:
        """Import idapro module once (one-time setup).

        Returns:
            True if successful, False otherwise.
        """
        if self._idapro_imported:
            return True

        try:
            # Setup sys.path for idalib
            idadir = os.environ.get("IDADIR")
            if idadir:
                idalib_python_path = Path(idadir) / "idalib" / "python"
                if (
                    idalib_python_path.exists()
                    and str(idalib_python_path) not in sys.path
                ):
                    sys.path.insert(0, str(idalib_python_path))
                    logger.debug("Added to sys.path: %s", idalib_python_path)

            # Worker-level fd isolation also covers native IDA output.
            original_stdout = sys.stdout
            try:
                sys.stdout = sys.stderr
                import idapro

                self._idapro = idapro
            finally:
                sys.stdout = original_stdout

            self._idapro_imported = True
            logger.info("idapro module imported successfully")
            return True

        except ImportError as e:
            logger.error("idapro module not available - idalib not installed: %s", e)
            return False
        except Exception as e:  # noqa: BLE001
            logger.error("Failed to import idapro: %s", e)
            return False

    def _check_existing_database(self, binary_path: Path) -> bool:
        """Check if database files exist for the binary.

        Args:
            binary_path: Path to the binary file.

        Returns:
            True if database files exist, False otherwise.
        """
        return bool(self._existing_database_files(binary_path))

    def _database_sidecar_paths(self, binary_path: Path) -> list[Path]:
        candidates: list[Path] = []
        seen: set[str] = set()
        for suffix in DATABASE_SIDECAR_SUFFIXES:
            for candidate in (
                binary_path.with_suffix(suffix),
                Path(str(binary_path) + suffix),
            ):
                key = str(candidate)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(candidate)
        return candidates

    def _existing_database_files(self, binary_path: Path) -> list[Path]:
        return [
            path for path in self._database_sidecar_paths(binary_path) if path.exists()
        ]

    def _delete_existing_database_files(self, binary_path: Path) -> list[Path]:
        removed: list[Path] = []
        for path in self._existing_database_files(binary_path):
            try:
                path.unlink()
            except FileNotFoundError:
                continue
            removed.append(path)
        return removed

    @staticmethod
    def _open_database_error_hint(
        code: int, run_auto_analysis: bool, has_existing_db: bool
    ) -> str:
        """Best-effort hint for idapro.open_database return code."""
        if code == 4:
            return (
                " (possible database lock/contention or incompatible open mode; "
                f"run_auto_analysis={run_auto_analysis}, existing_db={has_existing_db})"
            )
        return ""

    def _estimate_database_bytes(self, binary_path: Path) -> tuple[int, str]:
        sidecar_total = 0
        for path in self._database_sidecar_paths(binary_path):
            try:
                if path.is_file():
                    sidecar_total += int(path.stat().st_size)
            except OSError:
                continue
        if sidecar_total > 0:
            return sidecar_total, "existing-sidecars"

        try:
            binary_size = int(binary_path.stat().st_size)
        except OSError:
            binary_size = 0
        return (
            max(
                IDA_DB_ESTIMATE_MIN_BYTES,
                binary_size * IDA_DB_FALLBACK_BINARY_MULTIPLIER,
            ),
            "fallback",
        )

    def _check_database_disk_space(self, binary_path: Path) -> dict:
        estimated_db_bytes, estimate_source = self._estimate_database_bytes(binary_path)
        usage = shutil.disk_usage(str(binary_path.parent))
        required_bytes = int(estimated_db_bytes * IDA_DB_REQUIRED_MULTIPLIER)
        if int(usage.free) >= required_bytes:
            return {
                "ok": True,
                "available_bytes": int(usage.free),
                "required_bytes": required_bytes,
                "estimated_db_bytes": int(estimated_db_bytes),
                "estimate_source": estimate_source,
            }
        return {
            "success": False,
            "ok": False,
            "error_code": IDA_DB_SPACE_LOW,
            "error": (
                "insufficient free disk space for IDA database creation: "
                f"available={int(usage.free)}, required={required_bytes}"
            ),
            "binary_path": str(binary_path),
            "available_bytes": int(usage.free),
            "required_bytes": required_bytes,
            "estimated_db_bytes": int(estimated_db_bytes),
            "estimate_source": estimate_source,
            "hint": "free disk space, lower ida_pool_size, or run artifact cleanup",
        }

    def _open_database_internal(
        self, binary_path: Path, force_reanalyze: bool = False
    ) -> dict:
        """Open a binary database (internal method).

        Args:
            binary_path: Path to the binary file.
            force_reanalyze: Force recreate database even if it exists.

        Returns:
            Dictionary with 'success', 'path', 'existing_db', and optional 'error'.
        """
        # 1. Ensure idapro is imported
        if not self._import_idapro():
            return {"success": False, "error": "idapro module not available"}

        # 2. Close current database if one is open
        if self._ida_loaded:
            logger.info("Closing current database before opening new one")
            self._close_database_internal(save=True)

        # 3. Check if binary exists
        if not binary_path.exists():
            return {"success": False, "error": f"Binary not found: {binary_path}"}

        # 4. Check free space before any IDALib call or sidecar rebuild.
        existing_db_files = self._existing_database_files(binary_path)
        has_existing_db = bool(existing_db_files)
        disk_space = self._check_database_disk_space(binary_path)
        if not disk_space.get("ok"):
            logger.warning(
                "Refusing to open IDA database for %s: %s",
                binary_path,
                disk_space.get("error"),
            )
            return disk_space

        if force_reanalyze and existing_db_files:
            removed_files = self._delete_existing_database_files(binary_path)
            logger.info(
                "Removed %d existing database sidecar(s) before force_reanalyze: %s",
                len(removed_files),
                ", ".join(path.name for path in removed_files),
            )
            has_existing_db = False

        try:
            original_stdout = sys.stdout
            sys.stdout = sys.stderr

            logger.info("Opening database: %s", binary_path)

            # idapro.open_database(path, run_auto_analysis, ...) controls whether
            # auto-analysis should run; it does not accept a create/open-existing
            # mode flag. To force a rebuild we delete existing sidecars above and
            # then reopen with auto-analysis enabled.
            run_auto_analysis = not has_existing_db or force_reanalyze

            if run_auto_analysis:
                logger.debug("Opening database with auto-analysis enabled")
            else:
                logger.debug("Opening existing database without auto-analysis")

            # Open database
            result = self._idapro.open_database(str(binary_path), run_auto_analysis)

            if result != 0:
                sys.stdout = original_stdout
                hint = self._open_database_error_hint(
                    int(result),
                    run_auto_analysis=run_auto_analysis,
                    has_existing_db=has_existing_db,
                )
                return {
                    "success": False,
                    "error": f"open_database returned {result}{hint}",
                }

            logger.info("Database opened successfully")

            # Wait for auto-analysis to complete
            if run_auto_analysis:
                try:
                    import ida_auto

                    logger.info("Waiting for auto-analysis to complete...")
                    ida_auto.auto_wait()
                    logger.info("Auto-analysis completed")
                except Exception as e:  # noqa: BLE001
                    logger.warning("Could not wait for auto-analysis: %s", e)

            sys.stdout = original_stdout

            # Update state
            self._ida_loaded = True
            self.current_database_path = binary_path

            return {
                "success": True,
                "path": str(binary_path),
                "existing_db": has_existing_db and not force_reanalyze,
                "disk_space": disk_space,
            }

        except Exception as e:  # noqa: BLE001
            sys.stdout = original_stdout
            logger.error("Failed to open database: %s", e)
            logger.debug("Exception details: %s", traceback.format_exc())
            return {"success": False, "error": str(e)}

    def _close_database_internal(self, save: bool = True) -> dict:
        """Close current database (internal method).

        Args:
            save: Whether to save changes to the database.

        Returns:
            Dictionary with 'success', 'closed', 'saved', and optional 'error'.
        """
        if not self._ida_loaded:
            return {"success": True, "message": "No database was open"}

        if not self._idapro_imported or self._idapro is None:
            return {"success": False, "error": "idapro not imported"}

        try:
            old_path = self.current_database_path
            logger.info("Closing database: %s (save=%s)", old_path, save)

            original_stdout = sys.stdout
            sys.stdout = sys.stderr

            # Close database
            self._idapro.close_database(save=save)

            sys.stdout = original_stdout

            # Update state
            self._ida_loaded = False
            self.current_database_path = None

            logger.info("Database closed successfully")

            return {
                "success": True,
                "closed": str(old_path) if old_path else None,
                "saved": save,
            }

        except Exception as e:  # noqa: BLE001
            sys.stdout = original_stdout
            logger.error("Failed to close database: %s", e)
            logger.debug("Exception details: %s", traceback.format_exc())
            return {"success": False, "error": str(e)}

    def handle_request(self, request: dict) -> dict | None:
        """Handle a single JSON-RPC request.

        Args:
            request: Parsed JSON-RPC request dict.

        Returns:
            JSON-RPC response dict, or None for notifications.
        """
        if not isinstance(request, dict):
            return self._error_response(
                None, INVALID_REQUEST, "Request must be an object"
            )
        self._request_count += 1
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # Notifications never get a response or trigger request-only actions.
        if "id" not in request:
            if (
                request.get("jsonrpc") == "2.0"
                and method == "notifications/cancelled"
                and isinstance(params, dict)
            ):
                self.cancel_request(params.get("requestId"))
            return None
        if request.get("jsonrpc") != "2.0":
            return self._error_response(
                req_id, INVALID_REQUEST, "jsonrpc must be '2.0'"
            )
        if isinstance(req_id, bool) or not isinstance(req_id, (str, int, type(None))):
            return self._error_response(None, INVALID_REQUEST, "Invalid request id")

        if not method:
            self._error_count += 1
            return self._error_response(req_id, INVALID_REQUEST, "Missing method")

        if not isinstance(method, str):
            self._error_count += 1
            return self._error_response(
                req_id, INVALID_REQUEST, "Method must be a string"
            )

        if not isinstance(params, dict):
            self._error_count += 1
            return self._error_response(
                req_id, INVALID_PARAMS, "Params must be an object"
            )

        logger.debug(
            "Request #%d: method=%s id=%s", self._request_count, method, req_id
        )

        # TRACE level: log full request
        logger.trace(
            "Request #%d full content: %s",
            self._request_count,
            json.dumps(request, ensure_ascii=False, indent=2),
        )

        try:
            if method == "initialize":
                response = self._handle_initialize(req_id, params)
            elif method == "notifications/initialized":
                response = None
            elif method == "tools/list":
                response = self._handle_tools_list(req_id)
            elif method == "tools/call":
                response = self._handle_tools_call(req_id, params)
            elif method == "logging/setLevel":
                level = params.get("level")
                if not isinstance(level, str) or level not in LOG_LEVELS:
                    response = self._error_response(
                        req_id, INVALID_PARAMS, "Invalid logging level"
                    )
                else:
                    self._logging_level = level
                    response = self._success_response(req_id, {})
            elif method == "resources/list":
                response = self._success_response(
                    req_id, {"resources": self.session.list_resources()}
                )
            elif method == "resources/templates/list":
                response = self._success_response(req_id, {"resourceTemplates": []})
            elif method == "resources/read":
                try:
                    response = self._success_response(
                        req_id, self.session.read_resource(params.get("uri", ""))
                    )
                except (ValueError, TypeError) as error:
                    response = self._error_response(req_id, INVALID_PARAMS, str(error))
            elif method == "ping":
                response = self._success_response(req_id, {})
            else:
                self._error_count += 1
                response = self._error_response(
                    req_id, METHOD_NOT_FOUND, f"Method not found: {method}"
                )

            # TRACE level: log full response
            if response is not None:
                logger.trace(
                    "Response #%d full content: %s",
                    self._request_count,
                    json.dumps(response, ensure_ascii=False, indent=2),
                )

            return response
        except Exception as e:  # noqa: BLE001
            self._error_count += 1
            logger.error(
                "Internal error handling %s: %s", method, traceback.format_exc()
            )
            return self._error_response(req_id, INTERNAL_ERROR, str(e))

    def _handle_initialize(self, req_id: Any, params: dict) -> dict:
        """Handle MCP initialize request."""
        self._initialized = True
        requested = params.get("protocolVersion", PROTOCOL_VERSION)
        self._protocol_version = (
            requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[-1]
        )
        client_info = params.get("clientInfo", {})
        if not isinstance(client_info, dict):
            client_info = {}
        self.session.record(
            "initialized",
            client_info=client_info,
            protocol_version=self._protocol_version,
            session=self._session_metadata(params.get("_meta")),
        )
        logger.info(
            "Client connected: %s %s",
            client_info.get("name", "unknown"),
            client_info.get("version", ""),
        )
        return self._success_response(
            req_id,
            {
                "protocolVersion": self._protocol_version,
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "logging": {},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
                "instructions": INSTRUCTIONS,
            },
        )

    def _handle_tools_list(self, req_id: Any) -> dict:
        """Handle MCP tools/list request."""
        tools = []
        for tool_def in self.registry.list_tools():
            if self.tool_profile == "compact" and tool_def.name not in COMPACT_TOOLS:
                continue
            if self.tool_profile == "legacy" and tool_def.name in COMPACT_TOOLS - {
                "open_database",
                "close_database",
            }:
                continue
            metadata = {
                "name": tool_def.name,
                "description": tool_def.description,
                "inputSchema": tool_def.input_schema,
                "annotations": tool_def.annotations,
            }
            if tool_def.name in COMPACT_TOOLS:
                metadata["outputSchema"] = {"type": "object"}
            tools.append(metadata)
        logger.debug("Listed %d tools", len(tools))
        return self._success_response(req_id, {"tools": tools})

    def _handle_tools_call(self, req_id: Any, params: dict) -> dict:
        """Handle MCP tools/call request."""
        event = self.prepare_request(req_id)
        try:
            if event.is_set():
                return self._success_response(
                    req_id,
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": "Operation cancelled before execution",
                            }
                        ],
                        "isError": True,
                    },
                )
            return self._call_tool_impl(req_id, params)
        finally:
            with self._operations_lock:
                self._pending_requests.pop(req_id, None)

    def _call_tool_impl(self, req_id: Any, params: dict) -> dict:
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if not tool_name:
            self._error_count += 1
            return self._error_response(req_id, INVALID_PARAMS, "Missing tool name")

        if not isinstance(tool_name, str):
            self._error_count += 1
            return self._error_response(
                req_id, INVALID_PARAMS, "Tool name must be a string"
            )

        if not isinstance(arguments, dict):
            self._error_count += 1
            return self._error_response(
                req_id, INVALID_PARAMS, "Arguments must be an object"
            )
        arguments = dict(arguments)
        metadata = self._session_metadata(
            params.get("_meta"), arguments.pop("_meta", None)
        )

        tool_def = self.registry.get_tool(tool_name)
        if tool_def is None:
            self._error_count += 1
            return self._error_response(
                req_id, METHOD_NOT_FOUND, f"Tool not found: {tool_name}"
            )

        try:
            tool_def.validate_arguments(arguments)
        except ValueError as error:
            return self._error_response(req_id, INVALID_PARAMS, str(error))
        start_time = time.monotonic()
        from .tools.database import server_context

        token = self._request_context.set((req_id, uuid.uuid4().hex))
        self.session.record(
            "tool_start",
            request_id=req_id,
            tool=tool_name,
            arguments=arguments,
            session=metadata,
        )
        try:
            logger.info("Calling tool: %s(%s)", tool_name, arguments)
            with server_context(self):
                if self.manager is not None and tool_name not in RUNTIME_TOOLS:
                    target = self.manager.resolve_instance_id(None)
                    self.track_operation(target)
                    result = self.manager.execute_tool(
                        tool_name,
                        arguments,
                        target,
                        self.operation_id(),
                        self.cancel_event(),
                    )
                else:
                    result = tool_def.func(**arguments)
            failed = isinstance(result, dict) and (
                bool(result.get("error")) or result.get("success") is False
            )
            packaged = self.session.package(result)
            result_text = json.dumps(packaged, ensure_ascii=False, allow_nan=False)
            elapsed = time.monotonic() - start_time
            logger.info("Tool %s completed in %.3fs", tool_name, elapsed)
            payload = {
                "content": [{"type": "text", "text": result_text}],
                "isError": failed,
            }
            if isinstance(packaged, dict) and self._protocol_version != "2024-11-05":
                payload["structuredContent"] = packaged
            self.session.record(
                "tool_end",
                request_id=req_id,
                tool=tool_name,
                duration=elapsed,
                is_error=failed,
                output=packaged,
                result_artifact=(
                    packaged["artifact"] if packaged is not result else None
                ),
                session=metadata,
            )
            return self._success_response(req_id, payload)
        except Exception as e:  # noqa: BLE001
            self._error_count += 1
            elapsed = time.monotonic() - start_time
            logger.error(
                "Tool %s error after %.3fs: %s",
                tool_name,
                elapsed,
                traceback.format_exc(),
            )
            self.session.record(
                "tool_error",
                request_id=req_id,
                tool=tool_name,
                duration=elapsed,
                error=str(e),
                session=metadata,
            )
            return self._success_response(
                req_id,
                {
                    "content": [
                        {"type": "text", "text": json.dumps({"error": str(e)})}
                    ],
                    "isError": True,
                },
            )
        finally:
            with self._operations_lock:
                self._active_operations.pop(req_id, None)
            self._request_context.reset(token)

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
        self.set_notification_sink(self._write_response)

        logger.info("Server started, waiting for requests...")

        # 注册信号处理以实现优雅退出
        def _handle_signal(signum, frame):
            logger.info("Received signal %d, shutting down...", signum)
            raise KeyboardInterrupt

        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, _handle_signal)

        incoming = queue.Queue()

        def read_input():
            try:
                for line in sys.stdin:
                    # Read cancellation while the main thread waits on IDA.
                    try:
                        notification = json.loads(line)
                    except json.JSONDecodeError:
                        notification = None
                    if (
                        isinstance(notification, dict)
                        and notification.get("jsonrpc") == "2.0"
                        and notification.get("method") == "notifications/cancelled"
                        and "id" not in notification
                    ):
                        params = notification.get("params")
                        if isinstance(params, dict):
                            self.cancel_request(params.get("requestId"))
                    else:
                        if (
                            isinstance(notification, dict)
                            and notification.get("jsonrpc") == "2.0"
                            and notification.get("method") == "tools/call"
                            and isinstance(notification.get("params", {}), dict)
                            and isinstance(notification.get("id"), (str, int))
                            and not isinstance(notification.get("id"), bool)
                        ):
                            self.prepare_request(notification["id"])
                        incoming.put(line)
            finally:
                incoming.put(None)

        threading.Thread(target=read_input, name="ida-mcp-input", daemon=True).start()

        try:
            while True:
                line = incoming.get()
                if line is None:
                    break
                line = line.strip()
                if not line:
                    continue

                try:
                    request = json.loads(line)
                except json.JSONDecodeError as e:
                    self._error_count += 1
                    logger.warning("JSON parse error: %s (input: %s)", e, line[:200])
                    response = self._error_response(
                        None, PARSE_ERROR, f"Parse error: {e}"
                    )
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
        except Exception:  # noqa: BLE001
            logger.error("Unexpected error in main loop: %s", traceback.format_exc())

        self._shutdown()
        self.set_notification_sink(None)

    def _shutdown(self):
        """Perform graceful shutdown with statistics."""
        if self._closed:
            return
        self._closed = True
        if self.manager is not None:
            self.manager.shutdown()
        elif self._ida_loaded:
            self._close_database_internal(save=True)
        self.session.record("shutdown")
        elapsed = time.monotonic() - self._start_time
        logger.info(
            "Server shutting down. Stats: requests=%d, errors=%d, uptime=%.1fs",
            self._request_count,
            self._error_count,
            elapsed,
        )

    def _write_response(self, response: dict):
        """Write a JSON-RPC response to stdout."""
        try:
            # 确保使用原始 stdout
            output = (
                self._original_stdout
                if hasattr(self, "_original_stdout")
                else sys.stdout
            )
            with self._write_lock:
                output.write(
                    json.dumps(response, ensure_ascii=False, default=str) + "\n"
                )
                output.flush()
        except (BrokenPipeError, OSError) as e:
            logger.error("Failed to write response: %s", e)


def _parse_idle_timeout(value: str) -> float | None:
    from .backends import normalize_idle_timeout

    try:
        return normalize_idle_timeout(float(value))
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def main(argv: list[str] | None = None):
    """CLI entry point for ida-mcp-server."""
    from .cli import COMMANDS, run_command

    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in COMMANDS:
        return run_command(argv[0], argv[1:])
    parser = argparse.ArgumentParser(
        description="IDA Pro MCP server (stdio transport)",
        epilog="Commands: stdio, http, dashboard, logs, hook, install, update. Use COMMAND --help for options.",
    )
    parser.add_argument(
        "binary",
        nargs="?",
        default=None,
        help="Path to binary file to analyze",
    )
    parser.add_argument(
        "-v",
        "--verbose",
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
        help="Log file path (default: ~/.codex/log/ida-mcp-YYYYMMDD-HHMMSS.log for TRACE level)",
    )
    parser.add_argument("--backend", choices=["native", "nexus"], default="native")
    parser.add_argument(
        "--tool-profile", choices=["compact", "legacy", "full"], default="compact"
    )
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument(
        "--idle-timeout",
        type=_parse_idle_timeout,
        default=os.environ.get("IDA_MCP_IDLE_TIMEOUT") or "0",
        help="Release this session's idle Nexus headless leases after N seconds; 0 disables (IDA_MCP_IDLE_TIMEOUT)",
    )
    parser.add_argument(
        "--ida-dir",
        help="Pin an IDA installation directory (takes precedence over IDADIR)",
    )
    parser.add_argument(
        "--agent", default="unknown", help="Agent label for session traces"
    )
    parser.add_argument(
        "--session-log",
        nargs="?",
        const="auto",
        help="JSONL trace file; omit value for a private automatic path",
    )
    parser.add_argument(
        "--inline-limit",
        type=int,
        default=65536,
        help="Inline result budget in UTF-8 bytes",
    )
    parser.add_argument(
        "--print-config",
        action="store_true",
        help="Print ready-to-use stdio MCP JSON configuration",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Print environment diagnostics without initializing IDA",
    )
    parser.add_argument(
        "--dashboard", metavar="JSONL", help="Export a session log as standalone HTML"
    )
    parser.add_argument(
        "--output", default="ida-mcp-session.html", help="Dashboard HTML output file"
    )
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8737)
    args = parser.parse_args(argv)
    if args.idle_timeout is not None and args.backend != "nexus":
        parser.error("--idle-timeout requires --backend nexus")

    if args.ida_dir:
        candidate = Path(args.ida_dir).expanduser().resolve()
        if (candidate / "Contents" / "MacOS").is_dir():
            candidate = candidate / "Contents" / "MacOS"
        if not candidate.is_dir():
            parser.error("--ida-dir does not exist")
        os.environ["IDADIR"] = str(candidate)
    _auto_detect_idadir()
    if args.print_config:
        command_args = [
            "-u",
            "-m",
            "ida_mcp_stdio",
            "--backend",
            args.backend,
            "--tool-profile",
            args.tool_profile,
            "--agent",
            args.agent,
        ]
        if args.ida_dir:
            command_args.extend(["--ida-dir", os.environ["IDADIR"]])
        command_args.extend(["--idle-timeout", f"{args.idle_timeout or 0:g}"])
        if args.session_log:
            command_args.extend(["--session-log", args.session_log])
        if args.binary:
            command_args.append(str(Path(args.binary).expanduser().resolve()))
        print(
            json.dumps(
                {
                    "mcpServers": {
                        "ida-mcp-stdio": {
                            "command": sys.executable,
                            "args": command_args,
                        }
                    }
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    if args.doctor:
        import importlib.metadata

        versions = {}
        for package in ("idapro", "ida-domain", "ida-nexus", "mcp"):
            try:
                versions[package] = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                versions[package] = None
        print(
            json.dumps(
                {
                    "python": sys.version,
                    "executable": sys.executable,
                    "idadir": os.environ.get("IDADIR"),
                    "backend": args.backend,
                    "idle_timeout": args.idle_timeout,
                    "packages": versions,
                    "nexus_requirements": "Python >=3.11 and IDA >=9.4; use native for IDA 9.2",
                },
                indent=2,
            )
        )
        return
    if args.dashboard:
        from .dashboard import export_dashboard

        print(export_dashboard(Path(args.dashboard), Path(args.output)).resolve())
        return

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
        if args.log_file:
            log_file = Path(args.log_file).expanduser()
            log_dir = log_file.parent
        else:
            # 默认日志路径不要依赖当前工作目录，避免 cwd 不可写时报错
            log_dir = Path.home() / ".codex" / "log"
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            log_file = log_dir / f"ida-mcp-{timestamp}.log"

        # 创建日志目录
        log_dir.mkdir(parents=True, exist_ok=True)

        # 创建文件处理器
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(TRACE)  # 文件记录所有 TRACE 级别日志
        file_handler.setFormatter(logging.Formatter(log_format, date_format))
        root_logger.addHandler(file_handler)

        logger.info("TRACE logging enabled, writing to: %s", log_file)

    binary_path = Path(args.binary) if args.binary else None

    # 自动检测 IDADIR
    _auto_detect_idadir()

    # Import tool modules to trigger registration
    _import_tools()

    session_log = None
    if args.session_log:
        session_log = (
            Path(args.session_log).expanduser()
            if args.session_log != "auto"
            else Path.home()
            / ".local"
            / "state"
            / "ida-mcp-stdio"
            / (uuid.uuid4().hex + ".jsonl")
        )
    server = StdioMCPServer(
        binary_path=binary_path,
        backend=args.backend,
        tool_profile=args.tool_profile,
        max_workers=args.max_workers,
        session_log=session_log,
        agent=args.agent,
        inline_limit=args.inline_limit,
        idle_timeout=args.idle_timeout,
    )
    if session_log:
        logger.info("Session trace: %s", session_log)
    if args.transport == "http":
        from .http import serve

        serve(server, args.host, args.port)
        return

    # Inject server instance into database tools module
    from .tools import database

    database.set_server_instance(server)

    # If binary path specified, open it automatically (backward compatibility)
    if binary_path:
        if not binary_path.exists():
            logger.error("Binary file not found: %s", binary_path)
            sys.exit(1)

        try:
            result = server.manager.open_database(str(binary_path))
        except Exception as error:  # noqa: BLE001
            logger.error("Failed to open database: %s", error)
            server._shutdown()
            sys.exit(1)
        logger.info("Database loaded: %s", result.get("path"))
    else:
        logger.info(
            "No binary specified. Use 'open_database' tool to open a binary file."
        )

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
            import re

            def version_key(path):
                return tuple(int(part) for part in re.findall(r"\d+", path.name))

            for app in sorted(
                applications.glob("IDA*.app"), key=version_key, reverse=True
            ):
                macos_dir = app / "Contents" / "MacOS"
                if (macos_dir / "libidalib.dylib").exists():
                    candidates.append(str(macos_dir))
    elif system == "Linux":
        # Linux: versioned /opt/ida-pro-* installs plus legacy defaults.
        candidates.extend(sorted(glob.glob("/opt/ida-pro-*"), reverse=True))
        candidates.extend(
            [
                "/opt/ida-pro",
                "/opt/idapro",
                "/opt/ida",
                str(Path.home() / "idapro"),
                str(Path.home() / "ida"),
            ]
        )
    elif system == "Windows":
        # Windows: Program Files
        for pf in [
            os.environ.get("ProgramFiles", ""),
            os.environ.get("ProgramFiles(x86)", ""),
        ]:
            if not pf:
                continue
            pf_path = Path(pf)
            if pf_path.exists():
                for d in sorted(pf_path.glob("IDA*"), reverse=True):
                    if (d / "idalib.dll").exists() or (d / "idat64.exe").exists():
                        candidates.append(str(d))

    seen = set()
    for candidate in candidates:
        normalized = str(candidate).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)

        candidate_path = Path(normalized)
        if system == "Darwin":
            marker_found = (candidate_path / "libidalib.dylib").exists()
        elif system == "Windows":
            marker_found = (candidate_path / "idalib.dll").exists() or (
                candidate_path / "idat64.exe"
            ).exists()
        else:
            marker_found = (
                (candidate_path / "libidalib.so").exists()
                or (candidate_path / "idat64").exists()
                or (candidate_path / "idalib" / "python").is_dir()
            )

        if marker_found:
            os.environ["IDADIR"] = normalized
            logger.info("Auto-detected IDADIR: %s", normalized)
            return

    logger.debug("Could not auto-detect IDA installation directory")


def _import_tools():
    """Import tool modules to trigger registration via @register_tool."""
    modules = ["analysis", "memory", "types", "database", "runtime"]
    for mod_name in modules:
        try:
            __import__(f"ida_mcp_stdio.tools.{mod_name}", fromlist=[mod_name])
            logger.debug("Loaded tool module: %s", mod_name)
        except ImportError as e:
            logger.debug("Could not import %s tools: %s", mod_name, e)
