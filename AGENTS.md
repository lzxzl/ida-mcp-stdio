# Repository Guidelines

## Layout

- `src/ida_mcp_stdio/server.py`: CLI and stdio protocol. IDA runs outside the parent process.
- `backends.py` / `worker.py`: native per-database owners and the optional Nexus adapter.
- `execution.py`, `reference.py`, `session.py`: code execution, local API lookup, artifacts and traces.
- `tools/`: tool registration and database, analysis, memory and type helpers.
- `client.py`: Python stdio client. `http.py`: optional SDK HTTP transport.
- `tests/` and `tests/fixtures/`: permanent regression tests. `examples/`: runnable client examples.
- Human documentation starts at `README.md`.

## Development

Use Python 3.10+, four spaces, snake_case functions and PascalCase classes. Nexus requires Python 3.11+ and IDA 9.4+; native supports IDA 9.2. Keep IDA imports inside owner-side functions. Tool docstrings begin with a concise user-facing description; annotate parameters.

```sh
python -m pip install -e '.[dev,nexus,http]'
python -m pytest tests -q
python -m black --check src examples tests
python -m ruff check src examples tests
```

For real IDA validation and platform requirements, read `docs/TESTING.md`. Use temporary binaries and IDBs. Protocol and lifecycle changes need regression coverage for failure and cancellation paths.

## Git

Use short, imperative commit subjects. Include behavior, validation commands and relevant IDA / Python versions in PR descriptions. Preserve unrelated user changes. Keep generated databases, logs, analysis output, temporary probes and personal client configuration outside commits.
