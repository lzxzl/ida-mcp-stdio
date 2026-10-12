# Task benchmarks

[中文](BENCHMARK.md)

## Repeat the same analysis task

`benchmark run` uses IDAPython to query the first 32 functions, the first 32 strings and at most 64 imports. Call relationships are sampled from at most 256 heads per function. `separate` makes three calls; `batch` performs the same queries in one Python call.

The command copies the input to a temporary directory and creates, saves and closes a database there. The original file stays unchanged. Use an executable or library; existing IDBs are excluded from this benchmark.

```sh
clang -O0 -g examples/benchmark_sample.c -o /tmp/ida-mcp-sample
.venv/bin/ida-mcp-server benchmark run /tmp/ida-mcp-sample \
  --label separate --mode separate --output /tmp/separate.json
.venv/bin/ida-mcp-server benchmark run /tmp/ida-mcp-sample \
  --label batch --mode batch --output /tmp/batch.json
.venv/bin/ida-mcp-server benchmark compare /tmp/separate.json /tmp/batch.json \
  --output /tmp/comparison.json
```

Use `--ida-dir` to select an IDA installation and `--backend nexus` for the shared backend. Reports have mode 0600 and refuse existing destinations. They record the binary and query SHA-256 values, server version, IDA / Python versions and file type.

Comparison requires matching query code, binary, host and Python / IDA environments, tool profile, actual tool set and returned facts. Reports record both schema digests and whether they match; tool descriptions and schema contents may differ. Metrics cover workflow requests, elapsed time and JSON result bytes, excluding transport framing. Timing includes MCP execution and transport. Repeat runs and alternate their order to account for caches and scheduling.

On 2026-10-11, the sample returned identical facts in native IDA 9.2 and 9.4 runs, with three workflow calls for separate execution and one for batch execution. This measures no agent inference usage and does not reproduce the official approximately 20% token saving benchmark.

## Compare another stdio server

Save its launch command as a JSON array, such as `/path/to/official-command.json`:

```json
["/absolute/official/venv/bin/ida-mcp", "stdio", "--agent", "benchmark"]
```

```sh
.venv/bin/ida-mcp-server benchmark run /path/to/sample \
  --label official --server-command /path/to/official-command.json \
  --output /path/to/official-report.json
```

The server must support `open_database(path)`, `execute_python(code, instance_id, timeout)` and `close_database(instance_id)`. The array launches directly without a shell. Configure the external server's installation, environment and launch arguments yourself.

## Read recorded agent usage

```sh
.venv/bin/ida-mcp-server benchmark usage /path/to/transcript.jsonl \
  --agent codex --output /path/to/usage.json
```

Claude, Codex, OpenCode and ZCode parsers are supported. Usage covers the whole selected transcript and may include other tools or tasks. Missing tokens and cost stay unavailable. Agent comparisons need fresh isolated sessions, the same model, prompt and sample, and checks that the task succeeded. Keep scripted timing, schema tokenizer counts and actual model billing separate.
