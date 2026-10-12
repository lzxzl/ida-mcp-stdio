# Examples

[中文](README.md)

Install the project and configure IDA, then run the examples with the project virtual environment. Supply your own samples; the repository does not include IDA databases or large binaries.

| Example | Command | Content |
| --- | --- | --- |
| Basic calls | `.venv/bin/python examples/basic_usage.py /path/to/binary` | Function listing and decompilation |
| Analysis across databases | `.venv/bin/python examples/code_mode.py /path/to/a /path/to/b` | Compact tools, reference, and instance_id routing |
| Function pagination | `.venv/bin/python examples/pagination_example.py /path/to/binary` | Reads functions by page |
| Sequential batch analysis | `.venv/bin/python examples/batch_analysis.py /path/to/a /path/to/b` | Closes each database after processing its sample |
| Tool profile comparison | `.venv/bin/python examples/compare_tool_profiles.py /path/to/binary` | Equivalent results, request counts, payload bytes and timings; optional `--encoding o200k_base` |
| Session logging | `.venv/bin/python examples/trace_logging_example.py /path/to/binary` | Creates a JSONL trace |
| Repeatable task benchmark | `.venv/bin/ida-mcp-server benchmark run /path/to/binary --label batch --output /path/to/report.json` | Functions, call relationships, strings and imports; see [task benchmarks](../docs/BENCHMARK.en.md) |

The examples use the default native headless backend. To select an IDA version, set `IDADIR` or pass `--ida-dir` through the client's `server_args`. Automated tests remain in the local `tests/` directory and are excluded from Git.
