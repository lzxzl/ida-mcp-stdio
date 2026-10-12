# Migration to 0.3 / 0.4 / 0.5

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

## Changes in 0.4

- `reference` indexes all public APIs in the installed Domain package, reports its version and returns complete runnable examples. API and example matches have separate pagination; source is returned when requested.
- Nexus `--idle-timeout` expires inactive leases. It is disabled by default. The last managed headless owner saves and exits; another client's lease and GUI instances remain active. Lifecycle events enter JSONL, and disconnect warnings use MCP logging notifications.
- `dashboard` shows multiple sessions and explicitly linked agent transcripts. Tokens and costs use recorded values. `logs` exports raw traces, linked transcripts, artifacts and a ZIP manifest.
- `install` writes Codex, Claude Code / Desktop, OpenCode and ZCode formats with backups. `update` upgrades a venv and refreshes configurations. Optional hooks link Claude Code and supported Codex transcripts; Codex requires `/hooks` review.
- The [comparison example](../examples/compare_tool_profiles.py) measures equivalent legacy/compact analysis, including discovery overhead. Its payload/token measurements do not reproduce the official agent benchmark.

## Changes in 0.5

- `--gui-plugin` deploys the official GUI provider through HCLI, including environment checks, explicit IDAPython venv creation and command previews.
- `--hooks` adds an OpenCode V1 session plugin and durable ZCode hook transcripts. Claude Desktop still needs an explicitly linked export.
- Codex / Claude Code marketplace manifests, a Python launcher and usage guidance ship with source. The release workflow checks versions and assets; PyPI uploading needs a configured Trusted Publisher.
- `benchmark` repeats identical queries on binary copies and checks returned facts. Transcript usage is read separately. Real native 9.2 / 9.4 sample runs produced equivalent batch/separate facts; agent token savings remain unverified.
- `IDA_MCP_STDIO_STATE_DIR` configures storage. New Nexus installations require 0.13.4+, matching the current official GUI plugin.

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
