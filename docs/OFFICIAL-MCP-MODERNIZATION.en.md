# Migration to 0.3

[中文](OFFICIAL-MCP-MODERNIZATION.md)

## Defaults

- The server defaults to `stdio`, `native`, and `compact`. IDA moves out of the original server process into one idalib worker per database, while the parent handles the protocol.
- `compact` lists six entry tools. Use `--tool-profile legacy` for the original list, or `full` for all registered tools.
- Python `IDAMCPClient` still defaults to `legacy`, with existing helper calls retained.
- Opening a new database keeps existing targets open. Batch jobs should close targets they have finished processing.
- `open_database` adds `path` and retains `binary_path`; it returns an `instance_id`. Pass that ID explicitly when running code across databases.

## Added capabilities

`execute_python` supports composable analysis, persistent contexts, temporary scopes, top-level await, and structured output. `reference` looks up APIs in local helper and Domain source. Large results are saved as complete artifacts, and the Python client reads all pages automatically. JSONL sessions and HTML export are optional.

These interfaces draw on the [official Hex-Rays MCP](https://github.com/HexRaysSA/ida-mcp). This project has not reproduced its token-saving benchmark and makes no percentage improvement claim.

## Choosing a backend

| Requirement | Choice |
| --- | --- |
| Always headless, IDA 9.2 | `--backend native` |
| Always headless, IDA 9.4+ | `--backend native` |
| GUI or sharing across clients on 9.4+ | Install the Nexus extra and use `--backend nexus` |

Nexus reuses a matching GUI instance and starts a headless worker when no matching instance exists. Only native supports `close_database(save=False)` and `force_reanalyze`. Nexus leases, events, and crash recovery come from the official library.

## Updating clients

Use the absolute Python path for the current installation environment and run `-u -m ida_mcp_stdio`, avoiding global packages of the same name that point to another repository. Open samples per session with `open_database`; avoid fixed sample paths in global startup arguments.

Existing sessions need to reload MCP, and Claude Desktop needs a restart. See [client setup](MCP-CLIENT-SETUP.en.md) for configuration formats and [database management](DATABASE-MANAGEMENT.en.md) for lifecycle differences.
