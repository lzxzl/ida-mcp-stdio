# Logs and result files

[中文](TRACE-LOGGING.md)

## Runtime logs

Logs go to stderr by default. `--verbose` enables DEBUG, and `--log-level TRACE` records detailed protocol messages. `--log-file` writes logs to a file. With TRACE and no explicit path, the file is `~/.codex/log/ida-mcp-<timestamp>.log`.

```sh
.venv/bin/ida-mcp-server --log-level DEBUG --log-file /path/to/server.log
```

Runtime logs can contain tool arguments and analysis data. Keep log files out of Git.

## JSONL session traces

Session recording is off by default. When enabled, each request records tool arguments, results or errors, duration, session ID, and the agent label.

```sh
.venv/bin/ida-mcp-server --agent codex --session-log auto
# Or specify a path
.venv/bin/ida-mcp-server --session-log /path/to/session.jsonl
```

`auto` writes to `~/.local/state/ida-mcp-stdio/<random-id>.jsonl`; the startup log prints the path. Newly created directories use mode 0700, and log files use 0600. A recording failure produces a warning without changing the outcome of the completed operation.

Export a searchable local HTML file:

```sh
.venv/bin/ida-mcp-server --dashboard /path/to/session.jsonl \
  --output /path/to/session.html
```

The HTML contains the recorded data and loads no external resources.

## Large result artifacts

The default inline limit is 65536 bytes, adjustable with `--inline-limit`. Full results exceeding the limit are saved under `~/.local/state/ida-mcp-stdio/<session-id>/`, with file mode 0600. The response includes a path and resource URI.

Files remain after the session ends and need manual cleanup. Delete the corresponding JSONL file and session directory when they are no longer needed. Artifacts contain only what the executor captured; output beyond the stdout and stderr capture limits cannot be recovered. See [usage](USAGE.en.md) for pagination.
