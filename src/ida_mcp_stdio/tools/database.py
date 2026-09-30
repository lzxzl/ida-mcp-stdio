"""数据库管理工具 - 运行时打开/关闭/切换 IDA 数据库。

提供在单个 MCP server 会话中管理多个二进制文件数据库的工具。
支持批量分析工作流，无需重启 server。
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Annotated

from . import register_tool

# 全局 server 引用（通过工具上下文注入）
_server_instance: object | None = None
_server_context: ContextVar = ContextVar("ida_mcp_server", default=None)


def get_server_instance():
    """Return the request's server, with a compatibility fallback for embedding."""
    server = _server_context.get() or _server_instance
    if server is None:
        raise RuntimeError("Server instance not available")
    return server


@contextmanager
def server_context(server):
    token = _server_context.set(server)
    try:
        yield
    finally:
        _server_context.reset(token)


def set_server_instance(server):
    """由 server 在启动时调用，注入 server 实例引用。

    Args:
        server: StdioMCPServer 实例
    """
    global _server_instance
    _server_instance = server


@register_tool
def open_database(
    binary_path: Annotated[
        str | None, "Path to binary file (legacy name; alternatively use path)"
    ] = None,
    force_reanalyze: Annotated[bool, "Force recreate database even if exists"] = False,
    path: Annotated[
        str | None, "Path to binary or IDB, matching the official code-mode interface"
    ] = None,
    set_current: Annotated[bool, "Make this database the default target"] = True,
) -> dict:
    """Open or reuse a binary database, keeping other database instances open.

    Returns instance_id for explicit cross-binary routing. set_current selects
    the default target. Opening a new target does not close the previous target.
    If database files exist, opens them as-is unless force_reanalyze is True.
    When force_reanalyze is True, existing IDA database sidecars are deleted
    before reopening so idalib rebuilds the database and reruns auto-analysis.

    Args:
        binary_path: Path to the binary file to analyze
        force_reanalyze: If True, delete existing sidecars and rebuild database
                         with auto-analysis

    Returns:
        Dictionary with operation result:
        - success (bool): Whether operation succeeded
        - path (str): Path to the opened binary (if successful)
        - existing_db (bool): Whether an existing database was opened (if successful)
        - error (str): Error message (if failed)

    Example:
        >>> open_database("/path/to/binary.so")
        {'success': True, 'path': '/path/to/binary.so', 'existing_db': True}

        >>> open_database("/path/to/binary.so", force_reanalyze=True)
        {'success': True, 'path': '/path/to/binary.so', 'existing_db': False}
    """
    server = get_server_instance()
    if not binary_path and not path:
        raise ValueError("Specify path or binary_path")
    if binary_path and path and Path(binary_path).resolve() != Path(path).resolve():
        raise ValueError("path and binary_path refer to different files")
    resolved = Path(path or binary_path).expanduser().resolve()
    if server.manager is not None:
        return server.manager.open_database(str(resolved), set_current, force_reanalyze)

    try:
        result = server._open_database_internal(resolved, force_reanalyze)
        return result
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to open database: {e}"}


@register_tool
def close_database(
    save: Annotated[bool, "Whether to save changes to database"] = True,
    instance_id: Annotated[
        str | None, "Target database instance; omit for current"
    ] = None,
) -> dict:
    """Close the currently open database.

    Frees resources and allows opening a different database.
    Changes are saved by default.

    Args:
        save: If True (default), save changes before closing.
              If False, discard changes (useful for read-only analysis).

    Returns:
        Dictionary with operation result:
        - success (bool): Whether operation succeeded
        - closed (str): Path to the closed database (if successful)
        - saved (bool): Whether changes were saved (if successful)
        - message (str): Info message if no database was open
        - error (str): Error message (if failed)

    Example:
        >>> close_database()
        {'success': True, 'closed': '/path/to/binary.so', 'saved': True}

        >>> close_database(save=False)
        {'success': True, 'closed': '/path/to/binary.so', 'saved': False}
    """
    server = get_server_instance()
    if server.manager is not None:
        if instance_id is None and not server.manager.list_databases()["instances"]:
            return {"success": True, "message": "No database was open"}
        return server.manager.close_database(instance_id, save)

    try:
        result = server._close_database_internal(save)
        return result
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"Failed to close database: {e}"}


@register_tool
def get_current_database() -> dict:
    """Get information about the currently open database.

    Returns path, load status, and basic statistics about the current database.

    Returns:
        Dictionary with database information:
        - loaded (bool): Whether a database is currently open
        - path (str): Path to the currently open database (if loaded)
        - input_file (str): IDA's internal input file path (if loaded)
        - root_filename (str): Root filename from IDA (if loaded)
        - function_count (int): Number of functions in database (if available)
        - message (str): Info message if no database is open
        - error (str): Error details (if partially failed)

    Example:
        >>> get_current_database()
        {
            'loaded': True,
            'path': '/path/to/binary.so',
            'input_file': '/path/to/binary.so',
            'root_filename': 'binary.so',
            'function_count': 138
        }

        >>> get_current_database()  # When no database is open
        {'loaded': False, 'path': None, 'message': 'No database currently open'}
    """
    server = get_server_instance()
    if server.manager is not None:
        try:
            return server.manager.execute_tool("get_current_database", {})
        except ValueError:
            return {
                "loaded": False,
                "path": None,
                "message": "No database currently open",
            }

    # Check if database is loaded
    if not server._ida_loaded:
        return {
            "loaded": False,
            "path": None,
            "message": "No database currently open. Use 'open_database' tool to open a binary.",
        }

    try:
        import ida_nalt
        import idautils

        # Get basic information
        info = {
            "loaded": True,
            "path": str(server.current_database_path),
            "input_file": ida_nalt.get_input_file_path(),
            "root_filename": ida_nalt.get_root_filename(),
        }

        # Add statistics (optional, may fail for some databases)
        try:
            func_count = len(list(idautils.Functions()))
            info["function_count"] = func_count
        except Exception as e:  # noqa: BLE001
            info["function_count_error"] = str(e)

        return info

    except Exception as e:  # noqa: BLE001
        # Return basic info even if detailed info fails
        return {
            "loaded": True,
            "path": str(server.current_database_path),
            "error": f"Failed to get detailed info: {e}",
        }


def current_database_info() -> dict:
    """Read the active IDA owner's metadata without touching server or lease state."""
    import ida_loader
    import ida_nalt
    import idautils

    input_file = ida_nalt.get_input_file_path()
    idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    info = {
        "loaded": bool(input_file or idb_path),
        "path": input_file or idb_path,
        "input_file": input_file,
        "root_filename": ida_nalt.get_root_filename(),
    }
    try:
        info["function_count"] = sum(1 for _ in idautils.Functions())
    except (RuntimeError, TypeError) as error:
        info["function_count_error"] = str(error)
    return info
