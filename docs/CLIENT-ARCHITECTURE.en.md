# Architecture and transports

[中文](CLIENT-ARCHITECTURE.md)

## Native: headless

```text
MCP client
    ↕ stdio JSON-RPC
MCP server: protocol, tool registry, routing, results and logs
    ├─ worker A：idalib / IDAPython / IDB A
    ├─ worker B：idalib / IDAPython / IDB B
    └─ worker C：idalib / IDAPython / IDB C
```

Each database is held by an independent child process. IDA runs on that child's main thread; the parent does not load IDA. Requests within a worker run serially, and database contexts and failures are isolated from each other. The stdio server processes tool calls one at a time; a single connection does not schedule databases in parallel.

Before importing IDA, the worker separates its protocol output descriptor and redirects native stdout to stderr. The executor captures Python stdout and stderr and includes them in JSON, keeping logs out of protocol messages.

Native does not share IDBs across MCP servers. Multiple servers opening the same IDB can encounter lock contention. Use Nexus when sharing is required.

## Nexus: official instances and GUI sharing

```text
MCP client ↔ stdio server ↔ ida_nexus.DatabaseManager
                              ├─ Existing GUI / headless instance
                              └─ New headless worker
```

The server uses the official public Manager API to acquire database leases, execute code, save, and release connections. The official plugin schedules GUI operations on IDA's main thread. Clients sharing an IDB see each other's changes; the GUI can keep running after a lease is released.

Discovery, authentication, events and crash recovery come from Nexus. The server records Manager lifecycle events and sends disconnect warnings through MCP logging. The six default tools have no separate subscription for IDB modification events; the official `DatabaseHandle` exposes these underneath. See [database management](DATABASE-MANAGEMENT.en.md) for idle release.

Nexus 0.13.0 has an ABI issue in its macOS network filesystem probe. This project fixes the `statfs` symbol binding only in the server process on that platform and version, retaining the official network drive restriction.

## stdio

Each line is a JSON-RPC 2.0 message. stdout carries protocol traffic, and stderr carries logs. The protocol supports initialization, tool discovery and calls, resource reads, cancellation notifications and MCP logging. Supported versions are 2024-11-05, 2025-03-26, 2025-06-18, and 2025-11-25.

One stdio server serves one client connection. Different clients start separate servers and use Nexus to share databases across them. `IDAMCPClient` connects through bidirectional child-process pipes and does not use HTTP.

## Optional Streamable HTTP

```sh
.venv/bin/python -m pip install -e '.[http]'
.venv/bin/ida-mcp-server --transport http --backend native \
  --host 127.0.0.1 --port 8737
```

The MCP endpoint is `http://127.0.0.1:8737/mcp/`. HTTP uses the official MCP Python SDK. Each HTTP session has its own database manager, current selection, and artifact index. Nexus can still let these sessions share the underlying IDB.

HTTP accepts only loopback addresses and checks Host and Origin. The endpoint has no remote-access authentication; remote deployment needs an authenticated proxy. Nexus's internal authentication does not cover the MCP HTTP endpoint.

With recording enabled, each HTTP session writes `<base-stem>-<session-id>.jsonl` in the configured directory.
