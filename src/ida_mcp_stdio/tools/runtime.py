"""Compact, composable execution and database management tools."""

from __future__ import annotations

from typing import Annotated

from . import register_tool
from .database import get_server_instance


@register_tool
def execute_python(
    code: Annotated[
        str,
        "Python using IDAPython, optional db/ida_domain and tools helpers. Check reference first. Last expression is returned; variables persist per database. Full local user privileges, including file/process access and IDB changes.",
    ],
    instance_id: Annotated[
        str | None, "Database instance; omit to use the current target"
    ] = None,
    timeout: Annotated[float, "Positive finite execution timeout in seconds"] = 360,
    persist_globals: Annotated[
        bool, "Keep definitions/imports between calls to this database"
    ] = True,
) -> dict:
    """Run composable Python analysis or changes; returns result, stdout, stderr and errors.

    Filter and summarize inside Python to reduce context use. Existing analysis
    helpers are available as tools.decompile(), tools.list_funcs(), etc.
    A trailing expression returns a value; newly defined run(db), execute(db) or
    main(db) is called when no trailing expression exists. Native timeout/cancel
    terminates this database worker and loses unsaved changes; reopen afterward.
    """
    server = get_server_instance()
    target = server.manager.resolve_instance_id(instance_id)
    server.track_operation(target)
    return server.manager.execute_python(
        code,
        target,
        timeout,
        persist_globals,
        operation_id=server.operation_id(),
        cancel_event=server.cancel_event(),
    )


@register_tool
def reference(
    query: Annotated[
        str, "Keywords, symbol or method name to search in installed API sources"
    ],
    offset: Annotated[int, "Result offset"] = 0,
    limit: Annotated[int, "Maximum entries, 1 through 20"] = 8,
    include_source: Annotated[
        bool, "Include installed implementation examples"
    ] = False,
) -> dict:
    """Find offline, version-matched helper/Domain API signatures and examples without loading IDA."""
    from ..reference import get_reference_index

    return get_reference_index().search(query, offset, limit, include_source)


@register_tool
def list_databases() -> dict:
    """List database instances, current selection, backend and connection status."""
    return get_server_instance().manager.list_databases()


@register_tool
def save_database(
    instance_id: Annotated[
        str | None, "Database to save; omit for current target"
    ] = None,
) -> dict:
    """Save the selected IDB without closing it."""
    return get_server_instance().manager.save_database(instance_id)
