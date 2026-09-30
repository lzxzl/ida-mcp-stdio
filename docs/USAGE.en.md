# Usage

[中文](使用指南.md)

For installation and client setup, see the [README](../README.en.md) and [client setup](MCP-CLIENT-SETUP.en.md).

## Analysis workflow

1. Call `open_database(path=...)` and keep the returned `instance_id`.
2. Look up the API you need with `reference(query=...)`.
3. Run analysis with `execute_python(code=..., instance_id=...)`, filtering and summarizing results in Python.
4. Call `save_database` after changes, and `close_database` when finished.

```python
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient(tool_profile="compact") as client:
    client.initialize()
    target = client.open_database("/path/to/binary")
    print(client.reference("decompile", include_source=True))
    report = client.execute_python(
        "rows = tools.list_funcs(count=10)\n"
        "{'total': rows['total'], 'functions': rows['data']}",
        instance_id=target["instance_id"],
    )
    print(report["result"])
```

`IDAMCPClient` starts and cleans up its own stdio server process. Call `initialize()` before using tools. When the client context exits, the server attempts to save and release databases that are still open.

## Python execution

The execution environment provides `tools`, and you can import IDAPython modules. Installing `ida-domain` also provides `db` and `ida_domain`.

```python
import ida_funcs
rows = tools.list_funcs(count=100)
[f for f in rows["data"] if ida_funcs.get_func(int(f["addr"], 16))]
```

The return value is selected in this order: the last expression; a newly defined `run(db)` / `execute(db)` / `main(db)`; the variable `result`. If there is more than one entry function, the listed order decides which one runs. Entry functions can be synchronous or asynchronous, and code supports top-level `await`.

| Parameter | Default | Purpose |
| --- | --- | --- |
| `instance_id` | Current database | Selects the execution target |
| `timeout` | 360 seconds | Execution timeout; must be positive and finite |
| `persist_globals` | `true` | Keeps definitions and imports for later calls |

`persist_globals=False` uses a shallow copy of the existing context. New names are not retained. Existing mutable objects, modules, files, and the IDB can still change; those changes are not rolled back.

The response contains `result`, `stdout`, `stderr`, `elapsed`, and `output_truncated`. Python exceptions also include `error.type`, `error.message`, and `error.traceback`. Convert IDA objects to lists, dictionaries, or other JSON values before returning them. NaN, Infinity, and non-serializable objects cause the call to fail.

stdout and stderr are each capped at 1 MiB; excess output sets `output_truncated`. Native worker output from C-level stdout goes to the server log, not the captured Python stdout.

## Analysis helpers

| Category | Representative tools |
| --- | --- |
| Functions and names | `list_funcs`, `list_all_names`, `list_plt_stubs`, `export_funcs` |
| Decompilation and assembly | `decompile`, `decompile_batch`, `disasm` |
| Calls and cross-references | `xrefs_to`, `callees`, `list_callsites` |
| Search and data | `search_decompiled_code`, `find_bytes`, `imports`, `list_globals` |
| Memory and types | `get_bytes`, `get_int`, `get_string`, `search_structs`, `get_struct_definition`, `read_struct` |
| Structured facts | `extract_function_facts`, `extract_accesses`, `extract_lock_regions`, `extract_carrier_facts`, `extract_size_flow_facts` |
| microcode | `extract_selector_dispatch_microcode_facts`, `extract_indirect_callsite_microcode_facts` |

Use `reference` to look up parameters and implementations. It indexes this project's helpers and installed Domain source, and returns official links for the low-level IDAPython SDK documentation. Decompilation and microcode tools require a licensed Hex-Rays decompiler for the target architecture. Structured facts are analysis evidence; check them against decompilation and assembly.

## API lookup and notifications

`reference` returns `domain_version`, `entries` and `examples`. API entries use `total` / `next_offset`; examples use `examples_total` / `examples_next_offset`. Both use the query's `offset` and `limit`. `include_source=True` returns complete source. Lookup indexes locally installed source without loading IDA.

```python
api = client.reference("decompile", include_source=True)
print(api["domain_version"], api["examples"])
client.set_logging_level("warning")
for message in client.get_notifications():
    print(message["params"]["data"])
```

The Python client receives notifications in the background. `get_notifications()` drains up to the latest 200 messages. Reopen a disconnected Nexus database and use its new instance ID. Other clients set their threshold with MCP `logging/setLevel` and receive `notifications/message`.

## Large results and pagination

When a tool result exceeds the default 64 KiB limit, the response contains `artifact` metadata and a `preview`. The full JSON is saved as a private file. Only its MCP session can read the URI.

Other MCP clients read the URI with `resources/read` and parse `chunk` and `next_uri` from the response text. Join all chunks in order, then parse the JSON. Python `IDAMCPClient` handles these steps automatically. Files remain after the server exits and can be read through the response's `path`, but a new session cannot reuse the old URI.

Tool pagination, such as `list_funcs(offset=..., count=...)`, is separate from artifact file pagination. See [pagination_example.py](../examples/pagination_example.py).

## Errors

The Python client raises `MCPToolError` for tool failures, `MCPError` for protocol failures, and `MCPConnectionError` for connection failures. Python exceptions from `execute_python` are also treated as tool failures. Other MCP clients can inspect the error response for traceback and output.

A timeout or cancellation during native execution terminates the target worker; reopen the database afterward. Avoid automatic retries of writes that may have partially completed. See [database management](DATABASE-MANAGEMENT.en.md) for opening, capacity limits, and recovery.
