# Database management

[中文](DATABASE-MANAGEMENT.md)

## Tool parameters

| Tool | Parameters | Behavior |
| --- | --- | --- |
| `open_database` | `path` or the compatible `binary_path`; `set_current=true`; `force_reanalyze=false` | Opens a binary or IDB and returns an `instance_id` |
| `list_databases` | None | Native lists its held instances; Nexus also lists instances discoverable on this host |
| `save_database` | Optional `instance_id` | Saves the selected or current IDB |
| `close_database` | Optional `instance_id`; `save=true` | Native saves and closes the worker; Nexus saves and releases its lease |

Opening a new database keeps existing ones open. With native, `set_current=false` preserves the current selection. Nexus also preserves an existing selection, but selects the newly opened database when there is no current target. `execute_python(instance_id=...)` can access any held instance. Direct analysis tool calls use the current database.

## Multiple databases

```python
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient(tool_profile="compact") as client:
    client.initialize()
    left = client.open_database("/path/to/main.so")
    right = client.open_database("/path/to/helper.so", set_current=False)
    for target in (left, right):
        report = client.execute_python(
            "tools.list_funcs(count=5)", instance_id=target["instance_id"]
        )
        print(target["path"], report["result"])
        client.close_database(target["instance_id"])
```

Native normalizes paths and reuses targets already open in the same server. It allows four active workers by default, adjustable with `--max-workers`. At capacity, it rejects new databases until an existing target is closed.

Nexus listings can include `available` / `unavailable` instances not held by this session, with a null `instance_id`. Call `open_database` with the entry's `path` to obtain a session instance ID before executing or closing it. `current` / `attached` indicates an existing lease.

## Saving and rebuilding

A normal close or server EOF attempts to save and release databases. Call `save_database` after important changes to reduce data loss from an unexpected exit.

Native supports `close_database(save=False)` to skip saving on close. This does not undo writes to other files or restrict the code's write permissions. Nexus shares its IDB and rejects `save=False`.

Only native supports `force_reanalyze=true`. Close the active target first, then pass the original binary path. The server deletes the corresponding IDA database files and analyzes the binary again, losing manual changes in the old IDB. You cannot force a rebuild directly from an `.i64`, `.idb`, or database component.

## Timeouts, cancellation, and crashes

| Situation | Native behavior |
| --- | --- |
| Cancellation before execution | Skips the request and keeps the worker |
| Cancellation or timeout during Python or analysis tool execution | Terminates the target worker; other databases and the server remain available |
| Worker crash or protocol corruption | Reports a disconnected target and the error; does not retry automatically |
| Reopening a disconnected target | Cleans up the old worker and creates a new instance with a new `instance_id` |

The default execution timeout is 360 seconds, adjustable with `execute_python(timeout=...)`. Native open and auto-analysis requests have a separate 360-second limit. An open, save, or close operation that has already started does not support the same cancellation interrupt. Unsaved changes may be lost, and some changes may have completed before the failure.

Nexus uses the official implementation for timeouts, cancellation, shared leases, and recovery. Real-machine validation recovered a saved checkpoint by reopening after an IDA 9.4 headless worker exited unexpectedly. Unsaved data is not guaranteed to recover. Native does not have Nexus's automatic recovery mechanism.

## Idle release

```sh
.venv/bin/ida-mcp-server --backend nexus --idle-timeout 900
```

`--idle-timeout` is Nexus only, in seconds, and must be positive and finite. `0` disables it; disabled is the default. `IDA_MCP_IDLE_TIMEOUT` supplies an environment default, overridden by the command line.

The timer applies to this session's headless database leases and resets on database requests. Expiry invalidates this session's instance ID while preserving other clients' leases and the GUI. When the last lease expires, the official worker saves and closes the IDB. An immediate reopen waits up to 30 seconds for this known transition.

Lifecycle changes go to the enabled JSONL trace. MCP logging sends disconnect warnings with instance, reason and database state. Unsaved changes remain unprotected against abnormal process exit.
