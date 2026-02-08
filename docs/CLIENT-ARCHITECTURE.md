# Client Architecture Comparison

This document explains the three different client architectures available in IDA MCP stdio.

## Architecture Overview

### Mode 1: Auto-Start (Embedded Server)

```
┌─────────────────────────────────────┐
│  User Script (basic_usage.py)      │
│                                     │
│  ┌───────────────────────────────┐ │
│  │  IDAMCPClient                 │ │
│  │  - Creates subprocess         │ │
│  │  - Manages lifecycle          │ │
│  │  - Handles stdin/stdout       │ │
│  └───────────┬───────────────────┘ │
└──────────────┼─────────────────────┘
               │ subprocess.Popen
               │ stdin/stdout pipes
┌──────────────▼─────────────────────┐
│  Server Process                    │
│  python -m ida_mcp_stdio binary    │
│  - Loads IDA database              │
│  - Processes tool calls            │
│  - Returns JSON results            │
└────────────────────────────────────┘
```

**Characteristics:**
- ✅ Simplest to use
- ✅ Automatic cleanup
- ✅ No manual server management
- ❌ Less control over server lifecycle
- ❌ Harder to debug server issues

**Use Cases:**
- Quick analysis scripts
- Batch processing
- Production automation
- When you don't need to debug the server

---

### Mode 2: Separate Process (Managed Connection)

```
┌─────────────────────────────────────┐
│  User Script                        │
│  (connect_to_running_server.py)    │
│                                     │
│  ┌───────────────────────────────┐ │
│  │  PipeBasedMCPClient           │ │
│  │  - Connects to process        │ │
│  │  - Can read stderr            │ │
│  │  - More control               │ │
│  └───────────┬───────────────────┘ │
└──────────────┼─────────────────────┘
               │ subprocess.Popen
               │ stdin/stdout/stderr pipes
┌──────────────▼─────────────────────┐
│  Server Process                    │
│  python -m ida_mcp_stdio binary    │
│  - stderr visible to client        │
│  - Can be monitored separately     │
└────────────────────────────────────┘
```

**Characteristics:**
- ✅ More control over server
- ✅ Can capture and display server logs
- ✅ Better for debugging
- ✅ Can monitor server health
- ❌ Slightly more complex setup
- ❌ Still coupled to client lifecycle

**Use Cases:**
- Development and debugging
- When you need server logs
- Testing server behavior
- Monitoring server performance

---

### Mode 3: Pipe Connection (Fully Decoupled)

```
┌─────────────────────────────────────┐
│  Terminal 1: Server                 │
│  python -m ida_mcp_stdio binary     │
│  - Runs independently               │
│  - Reads from stdin                 │
│  - Writes to stdout                 │
└──────────────┬──────────────────────┘
               │
               │ Shell pipe or
               │ Named FIFO or
               │ File descriptors
               │
┌──────────────▼──────────────────────┐
│  Terminal 2: Client                 │
│  (separate_server_client.py)        │
│  - Reads from stdin                 │
│  - Writes to stdout                 │
│  - Completely independent           │
└─────────────────────────────────────┘
```

**Characteristics:**
- ✅ Complete separation of concerns
- ✅ Server can outlive client
- ✅ Multiple clients can connect (with proper setup)
- ✅ Ideal for IDE integration
- ❌ Most complex setup
- ❌ Manual lifecycle management
- ❌ Requires understanding of pipes/FIFOs

**Use Cases:**
- IDE/editor integration
- Long-running analysis sessions
- Multiple client connections
- Advanced debugging scenarios
- When server needs to persist

---

## Communication Protocol

All three modes use the same JSON-RPC 2.0 protocol over stdio:

### Request (Client → Server)
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "decompile",
    "arguments": {"addr": "main"}
  },
  "id": 1
}
```

### Response (Server → Client)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"addr\":\"main\",\"code\":\"int main() {...}\"}"
      }
    ],
    "isError": false
  }
}
```

### Log Output (Server → stderr)
```
2026-02-08 14:21:27 [INFO] ida-mcp-stdio: Opening database: binary.so
2026-02-08 14:21:27 [INFO] ida-mcp-stdio: Database opened successfully
```

---

## Implementation Comparison

### Mode 1: Auto-Start

```python
from ida_mcp_stdio import IDAMCPClient

# One-liner setup
with IDAMCPClient("binary.so", verbose=True) as client:
    client.initialize()
    result = client.decompile("main")
    # Server automatically cleaned up on exit
```

**Key Code:**
- `subprocess.Popen()` with `stdin=PIPE, stdout=PIPE`
- `stderr=None` when verbose (inherits parent's stderr)
- `stderr=PIPE` when not verbose (captures logs)

---

### Mode 2: Separate Process

```python
from examples.connect_to_running_server import PipeBasedMCPClient

# Explicit command
command = ["python", "-m", "ida_mcp_stdio", "binary.so"]
with PipeBasedMCPClient.connect_to_command(command) as client:
    client.initialize()
    result = client.call_tool("decompile", {"addr": "main"})
    # Can read stderr separately
```

**Key Code:**
- `subprocess.Popen()` with `stdin=PIPE, stdout=PIPE, stderr=PIPE`
- Can call `process.stderr.read()` to get logs
- More control over process lifecycle

---

### Mode 3: Pipe Connection

```bash
# Terminal 1: Start server
python -m ida_mcp_stdio binary.so 2>server.log

# Terminal 2: Connect client (via pipe)
python -m ida_mcp_stdio binary.so 2>/dev/null | \
    python examples/separate_server_client.py
```

```python
from examples.separate_server_client import ExternalMCPClient

# Uses sys.stdin/stdout directly
client = ExternalMCPClient()
client.initialize()
result = client.call_tool("decompile", {"addr": "main"})
```

**Key Code:**
- `sys.stdin.readline()` for reading
- `sys.stdout.write()` for writing
- No subprocess management
- Relies on external pipe setup

---

## Choosing the Right Mode

### Use Mode 1 (Auto-Start) if:
- ✓ You want the simplest API
- ✓ You're writing analysis scripts
- ✓ You don't need to debug the server
- ✓ You want automatic cleanup

### Use Mode 2 (Separate Process) if:
- ✓ You're developing/debugging
- ✓ You need to see server logs
- ✓ You want more control
- ✓ You're testing server behavior

### Use Mode 3 (Pipe Connection) if:
- ✓ You're integrating with an IDE
- ✓ You need server persistence
- ✓ You want complete decoupling
- ✓ You're building advanced tooling

---

## Advanced: Named Pipes (FIFO)

For Mode 3, you can use named pipes for bidirectional communication:

```bash
# Create FIFOs
mkfifo /tmp/ida_in /tmp/ida_out

# Terminal 1: Server
python -m ida_mcp_stdio binary.so \
    < /tmp/ida_in > /tmp/ida_out 2>server.log &

# Terminal 2: Client (requires custom implementation)
# Read from /tmp/ida_out, write to /tmp/ida_in
```

**Note:** This requires custom client code to read/write from FIFOs instead of stdin/stdout.

---

## Performance Considerations

| Aspect | Mode 1 | Mode 2 | Mode 3 |
|--------|--------|--------|--------|
| Startup overhead | Medium | Medium | Low (if server pre-started) |
| Communication latency | Low | Low | Low |
| Memory overhead | Low | Low | Low |
| Server reuse | No | No | Yes |
| Parallel clients | No | No | Possible |

---

## Security Considerations

All modes use local stdio communication, which is secure by default:

- ✅ No network exposure
- ✅ No authentication needed
- ✅ Process isolation via OS
- ⚠️ Mode 3 with FIFOs: ensure proper file permissions

---

## Debugging Tips

### Mode 1: Auto-Start
```python
# Enable verbose to see server logs
with IDAMCPClient("binary.so", verbose=True) as client:
    # Server logs appear in terminal
    pass
```

### Mode 2: Separate Process
```python
client = PipeBasedMCPClient.connect_to_command(command)
# Read server stderr
if client._process.stderr:
    logs = client._process.stderr.read(1024)
    print(f"Server logs: {logs}")
```

### Mode 3: Pipe Connection
```bash
# Redirect server logs to file
python -m ida_mcp_stdio binary.so 2>debug.log | \
    python examples/separate_server_client.py

# In another terminal, watch logs
tail -f debug.log
```

---

## Summary

- **Mode 1 (Auto-Start)**: Best for most users, simplest API
- **Mode 2 (Separate Process)**: Best for development, more control
- **Mode 3 (Pipe Connection)**: Best for integration, most flexible

All modes use the same protocol and provide the same functionality. Choose based on your use case and complexity requirements.
