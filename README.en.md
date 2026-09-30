# ida-mcp-stdio

[中文](README.md)

An MCP server for IDA Pro, using stdio by default. It runs without a GUI, keeps multiple databases open, and lets you combine analysis tools in Python. The optional official Nexus backend supports GUI sharing.

## Installation

Install and license IDA Pro, and make sure idalib is available.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/ida-mcp-server --doctor
```

| Backend | Python | IDA | Behavior |
| --- | --- | --- | --- |
| `native`, default | 3.10+ | idalib 9.0+; tested with 9.2 and 9.4 | Always headless; one independent worker per database |
| `nexus` | 3.11+ | 9.4+ | Reuses official instances and the GUI; starts a headless worker when no matching instance exists |

To use Nexus, install it with `.venv/bin/python -m pip install -e '.[nexus]'`. The backend targets the 9.4+ API and has been tested on a real IDA 9.4 installation.

## Starting the server

```sh
# Headless stdio, macOS example
.venv/bin/ida-mcp-server --backend native \
  --ida-dir '/Applications/IDA Professional 9.4.app/Contents/MacOS'

# IDA 9.2 also uses native; select its installation path
# Nexus / GUI sharing
.venv/bin/ida-mcp-server --backend nexus \
  --ida-dir '/Applications/IDA Professional 9.4.app/Contents/MacOS'
```

If you omit the binary path, the client opens a database with `open_database`. You can also append a binary or IDB path to the command. An MCP client connects to the stdio server through bidirectional pipes.

`--ida-dir` takes precedence over `IDADIR`. If neither is set, the server detects the installation directory. GUI reuse requires the official plugin and an IDAPython environment; see [client setup](docs/MCP-CLIENT-SETUP.en.md).

## Tools

The default `compact` profile lists six tools:

| Tool | Purpose |
| --- | --- |
| `open_database` | Opens or reuses a database and returns an `instance_id` |
| `list_databases` | Lists database instances, their status, and the current target |
| `save_database` | Saves the selected database |
| `close_database` | Saves and closes a native worker, or releases a Nexus lease |
| `reference` | Looks up signatures, documentation, and source for local helpers and the Domain API, offline |
| `execute_python` | Runs Python in a selected database, combining IDAPython with existing analysis tools |

`--tool-profile legacy` lists the original tools; `full` lists every registered tool. Registered tools omitted from the list can still be called by name. The Python client defaults to `legacy`.

## Python example

```python
from ida_mcp_stdio import IDAMCPClient

with IDAMCPClient(tool_profile="compact") as client:
    client.initialize()
    target = client.open_database("/path/to/binary")
    report = client.execute_python(
        "rows = tools.list_funcs(count=20)\n"
        "{'total': rows['total'], 'names': [f['name'] for f in rows['data']]}",
        instance_id=target["instance_id"],
    )
    print(report["result"])
    client.close_database(target["instance_id"])
```

Python variables persist separately for each database. The last expression becomes the return value. Code supports top-level `await`; execution returns stdout, stderr, elapsed time, and structured exceptions. Return values must be JSON serializable.

The native backend keeps up to four databases open by default. A timeout or cancellation during execution terminates the target worker, so unsaved changes may be lost. The MCP server and other databases remain available. Large results are saved as local artifacts, and the Python client reads all pages automatically.

Python code has the current user's file, process, and IDB permissions. Execution is not sandboxed.

## Documentation

- [Usage](docs/USAGE.en.md): code execution, analysis tools, and result retrieval.
- [Client setup](docs/MCP-CLIENT-SETUP.en.md): Codex, Claude, OpenCode, ZCode, and the GUI environment.
- [Database management](docs/DATABASE-MANAGEMENT.en.md): routing, saving, closing, and recovery.
- [Architecture](docs/CLIENT-ARCHITECTURE.en.md), [logging](docs/TRACE-LOGGING.en.md), and [development](docs/MCP-SERVER-DEVELOPMENT-GUIDE.en.md).
- [0.3 migration](docs/OFFICIAL-MCP-MODERNIZATION.en.md), [validation scope](docs/TESTING.en.md), and [runnable examples](examples/README.en.md).

References: [Hex-Rays MCP introduction](https://hex-rays.com/blog/hex-rays-ida-mcp-server), [official implementation](https://github.com/HexRaysSA/ida-mcp).
