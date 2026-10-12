# Logs, dashboard and exports

[中文](TRACE-LOGGING.md)

## Recording

Runtime logs go to stderr. `--verbose` enables DEBUG; `--log-level TRACE` includes protocol details. `--log-file` selects a file. TRACE without a path uses `~/.codex/log/ida-mcp-<timestamp>.log`.

JSONL recording is optional:

```sh
.venv/bin/ida-mcp-server --agent codex --session-log auto
# Or choose a file
.venv/bin/ida-mcp-server --session-log /path/to/session.jsonl
```

`auto` writes to `~/.local/state/ida-mcp-stdio/<session-id>.jsonl`. `IDA_MCP_STDIO_STATE_DIR` selects another absolute directory for default traces, artifacts, transcripts and the dashboard. The trace records initialization, tool arguments, results, errors, durations and Nexus lifecycle events. New state directories use mode 0700; files use 0600. Recording errors produce warnings without changing completed tool results.

## Dashboard

```sh
.venv/bin/ida-mcp-server dashboard --open
# A different trace directory
.venv/bin/ida-mcp-server dashboard --state-dir /path/to/traces --port 8740
# A standalone HTML view of one trace
.venv/bin/ida-mcp-server dashboard --session /path/to/session.jsonl \
  --export /path/to/session.html
```

The live dashboard binds to loopback only. It refreshes local sessions and supports search, agent/event filters, tool latency, errors and a combined MCP/agent timeline. HTML exports include the selected session and its linked transcripts, with no external resources. The older `--dashboard JSONL --output HTML` form still works.

## Linking agent transcripts

Install adapters with `install --hooks` for Claude Code, supported Codex CLI, OpenCode and ZCode. Codex requires `/hooks` review before new or changed hooks run. Adapters add the transcript path to tool input `_meta`; the server strips it before validating or running the tool.

The OpenCode V1 plugin reads only active sessions that invoke IDA tools and refreshes private snapshots after tool and session events. ZCode saves temporary hook transcripts and IDA tool events in private session files. Snapshot paths are fixed at installation; reinstall or update with `--hooks` after changing `IDA_MCP_STDIO_STATE_DIR`. Existing disabled settings are preserved; see [client setup](MCP-CLIENT-SETUP.en.md). ZCode tokens and cost remain unavailable when hooks supply no usage.

Parsers still read Claude, Codex, Copilot, OpenCode and ZCode records, including the existing `hook copilot` adapter. Other clients can supply their recorded session path in `_meta`, for example through the Python client:

```python
client.call_tool("reference", {"query": "decompile"}, metadata={
    "codex_session_path": "/absolute/path/rollout.jsonl"
})
```

Use the matching `<agent>_session_path` key; Claude Code uses `claude_session_path`. The dashboard reads only explicitly linked transcripts. It does not scan client histories. Tokens and costs come from recorded fields; unavailable cost stays unavailable. Codex cumulative usage uses the latest checkpoint. Usage covers the linked transcript, which can include work outside this MCP server; shared transcripts can overlap across sessions. Task time uses recorded activity intervals; session elapsed time spans the first and last trace records.

## ZIP export

```sh
.venv/bin/ida-mcp-server logs --output /path/to/ida-mcp-logs.zip
# Limit to one trace and omit agent transcripts
.venv/bin/ida-mcp-server logs --session /path/to/session.jsonl \
  --no-transcripts --output /path/to/one-session.zip
```

The ZIP contains raw selected traces, referenced result files and linked transcripts. `ida-mcp-logs.json` records original paths, archive paths, sizes, SHA-256 hashes and missing/skipped-file warnings. Existing destinations are refused. New archives use mode 0600. Review the contents before sharing: analysis data and conversations are preserved.

## Large results and cleanup

Results over `--inline-limit` (65536 bytes by default) are stored under `~/.local/state/ida-mcp-stdio/<session-id>/`. Responses include the path and resource URI. See [usage](USAGE.en.md) for pagination.

Files remain after shutdown. Delete the relevant JSONL and session directory when finished. Artifacts retain captured results; output beyond executor capture limits cannot be recovered. Keep logs, exports and result files out of Git.
