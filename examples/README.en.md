# Examples

[中文](README.md)

Install the project and configure IDA, then run the examples with the project virtual environment. Supply your own samples; the repository does not include IDA databases or large binaries.

| Example | Command | Content |
| --- | --- | --- |
| Basic calls | `.venv/bin/python examples/basic_usage.py /path/to/binary` | Function listing and decompilation |
| Analysis across databases | `.venv/bin/python examples/code_mode.py /path/to/a /path/to/b` | Compact tools, reference, and instance_id routing |
| Function pagination | `.venv/bin/python examples/pagination_example.py /path/to/binary` | Reads functions by page |
| Sequential batch analysis | `.venv/bin/python examples/batch_analysis.py /path/to/a /path/to/b` | Closes each database after processing its sample |
| Session logging | `.venv/bin/python examples/trace_logging_example.py /path/to/binary` | Creates a JSONL trace |

The examples use the default native headless backend. To select an IDA version, set `IDADIR` or pass `--ida-dir` through the client's `server_args`. Automated tests remain in the local `tests/` directory and are excluded from Git.
