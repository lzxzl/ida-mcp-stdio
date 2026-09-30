"""Main-thread IDA owner with an output channel isolated from native stdout."""

from __future__ import annotations

import json
import os
import sys
import traceback
from types import SimpleNamespace

from .execution import execute_code


def main() -> None:
    # Keep a private protocol descriptor BEFORE IDA imports. Even os.write(1)
    # and C/C++ library output now go to stderr instead of the response pipe.
    protocol = os.fdopen(
        os.dup(sys.stdout.fileno()), "w", encoding="utf-8", buffering=1
    )
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    sys.stdout = sys.stderr
    from .server import (
        RUNTIME_TOOLS,
        StdioMCPServer,
        _auto_detect_idadir,
        _import_tools,
    )
    from .tools import get_registry
    from .tools.database import set_server_instance

    _auto_detect_idadir()
    _import_tools()
    server = StdioMCPServer(backend="embedded")
    set_server_instance(server)
    namespace = {
        "tools": SimpleNamespace(
            **{
                tool.name: tool.func
                for tool in get_registry().list_tools()
                if tool.name not in RUNTIME_TOOLS or tool.name == "get_current_database"
            }
        )
    }
    try:
        for line in sys.stdin:
            request = json.loads(line)
            result = {}
            try:
                action = request["action"]
                if action == "open":
                    from pathlib import Path

                    result = server._open_database_internal(
                        Path(request["path"]), request.get("force_reanalyze", False)
                    )
                    if result.get("success"):
                        try:
                            import ida_domain

                            namespace.update(
                                ida_domain=ida_domain, db=ida_domain.Database.open()
                            )
                        except ImportError:
                            pass
                elif action == "execute":
                    result = execute_code(
                        request["code"], namespace, request.get("persist_globals", True)
                    )
                elif action == "tool":
                    result = get_registry().call_tool(
                        request["name"], request["arguments"]
                    )
                elif action == "save":
                    import ida_loader

                    path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
                    if not path or not ida_loader.save_database(path, 0):
                        raise RuntimeError("IDA failed to save the database")
                    result = {"saved": True, "idb_path": path}
                elif action == "close":
                    result = server._close_database_internal(request.get("save", True))
                else:
                    raise ValueError(f"Unknown worker action: {action}")
                response = {"id": request["id"], "result": result}
                # User code must explicitly convert IDA objects; never silently
                # turn objects, NaN or Infinity into misleading JSON strings.
                encoded = json.dumps(response, ensure_ascii=False, allow_nan=False)
            except Exception as error:  # noqa: BLE001
                encoded = json.dumps(
                    {
                        "id": request["id"],
                        "error": f"{type(error).__name__}: {error}\n{traceback.format_exc()}",
                    }
                )
            protocol.write(encoded + "\n")
            protocol.flush()
            if request["action"] == "close" and result.get("success"):
                break
    finally:
        if server._ida_loaded:
            server._close_database_internal(save=True)
        protocol.close()


if __name__ == "__main__":
    main()
