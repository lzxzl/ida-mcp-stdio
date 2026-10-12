# Development

[中文](MCP-SERVER-DEVELOPMENT-GUIDE.md)

## Modules

| Path | Responsibility |
| --- | --- |
| `src/ida_mcp_stdio/server.py` | CLI, stdio JSON-RPC, request and cancellation routing |
| `backends.py`, `worker.py` | Native worker lifecycle and the Nexus adapter |
| `execution.py` | Python execution, contexts, output, and exceptions |
| `reference.py` | Local source API index |
| `session.py` | Artifacts and JSONL recording |
| `dashboard.py`, `transcripts.py`, `logs.py`, `hooks.py` | Local dashboard, transcript parsing, ZIP exports and client hooks |
| `install.py`, `cli.py` | Client installation, updates and auxiliary commands |
| `gui.py` | Official HCLI GUI deployment planning and execution |
| `benchmark.py`, `assets/opencode-session.js` | Repeatable analysis task benchmarks and OpenCode active-session transcripts |
| `http.py` | Optional MCP SDK HTTP transport |
| `client.py` | Python stdio client and paginated retrieval of complete results |
| `tools/` | Tool registration, database control, analysis, memory, and type helpers |
| `structured_facts.py` | Structured fact fields and validation |
| `nexus_compat.py` | The Darwin / Nexus 0.13.0 statfs ABI fix |

## Development environment

The commands below that use the test directory apply only to workspaces retaining the local tests. Cloning the repository does not include that directory.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev,nexus,http]'
.venv/bin/python -m pytest tests -q
.venv/bin/python -m black --check src examples tests
.venv/bin/python -m ruff check src examples tests
.venv/bin/python -m pip wheel . --no-deps --wheel-dir dist
```

For native-only development, install `.[dev]`. Nexus requires Python 3.11+, and HTTP tests need the HTTP extra.

## Adding tools

Use `@register_tool` in `tools/`. Annotate parameters; `Annotated` supplies their descriptions. The full docstring becomes the tool description, so write a short summary on the first line. Import new modules in `server._import_tools()`.

```python
from typing import Annotated
from . import register_tool

@register_tool
def count_functions(limit: Annotated[int, "Result limit"] = 20) -> dict:
    import idautils
    addresses = list(idautils.Functions())
    return {"total": len(addresses), "sample": [hex(ea) for ea in addresses[:limit]]}
```

Inputs and results must use JSON-compatible types. Analysis tools run in the IDA owner; database control tools are routed in the parent server. Change the profile only when a tool needs to join the six default entry tools. New helpers are usually composed through `tools.<name>()`.

Keep IDA imports inside the functions that execute them so server initialization and reference lookups do not need to load IDA. New tools need tests for argument validation and errors, plus IDA checks using isolated temporary samples. When structured facts change, update schema validation and client wrappers together.

## Protocol and failure boundaries

stdout carries only protocol messages; logs go to stderr. Keep response IDs matched, notifications unanswered, JSON encoding strict, and cancellation state isolated. Do not automatically retry database writes.

The native worker owns IDA's main thread. The parent process must not call IDAPython. Nexus schedules work through the public `DatabaseManager` API. Compatibility fixes for known dependency defects must be limited to the affected platform and version.

## Tests and commits

Local tests are in `tests/`, with fixtures in `tests/fixtures/`. Both are ignored by Git and excluded from the published repository. Real IDA cases are skipped by default; see [TESTING](TESTING.en.md) for commands and validation scope.

Commit descriptions should state behavior changes, validation commands, and the IDA and Python versions used. Commit source and documentation. Keep tests, analysis databases, logs, temporary samples, and personal client configuration local.
