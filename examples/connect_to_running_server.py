#!/usr/bin/env python3
"""Example of connecting to a separately running server via subprocess pipes.

This demonstrates a more practical approach where the client manages
the connection to an already-running server process.

Usage:
    # Start server in one terminal:
    python -m ida_mcp_stdio so/libbluetooth.so --verbose

    # In another terminal, get the server's PID and connect:
    python examples/connect_to_running_server.py <server_pid>
    
    # Or use the simpler pipe approach:
    python -m ida_mcp_stdio so/libbluetooth.so 2>/dev/null | python examples/connect_to_running_server.py --pipe
"""

import json
import subprocess
import sys
import threading
from typing import Any, Optional


class PipeBasedMCPClient:
    """Client that connects to a server via explicit pipe/process.
    
    This is useful when you want to:
    1. Connect to an already-running server
    2. Have more control over the server lifecycle
    3. Debug server/client separately
    """

    def __init__(self, process: subprocess.Popen, timeout: float = 300):
        """Initialize client with an existing process.
        
        Args:
            process: subprocess.Popen object with stdin/stdout pipes.
            timeout: Default request timeout in seconds.
        """
        self._process = process
        self.timeout = timeout
        self._request_id = 0

    @classmethod
    def connect_to_command(cls, command: list[str], **kwargs) -> "PipeBasedMCPClient":
        """Connect to a server by running a command.
        
        Args:
            command: Command to execute (e.g., ["python", "-m", "ida_mcp_stdio", "binary.so"])
            **kwargs: Additional arguments for subprocess.Popen
            
        Returns:
            Connected client instance.
        """
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            **kwargs
        )
        return cls(process)

    def _next_id(self) -> int:
        """Get the next request ID."""
        self._request_id += 1
        return self._request_id

    @property
    def is_running(self) -> bool:
        """Check if the server process is still running."""
        return self._process.poll() is None

    def _send_request(
        self,
        method: str,
        params: Optional[dict] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Send a JSON-RPC request and return the result."""
        if not self.is_running:
            raise ConnectionError(
                f"Server process is not running (exit code: {self._process.returncode})"
            )

        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._next_id(),
        }

        request_line = json.dumps(request, ensure_ascii=False) + "\n"
        try:
            self._process.stdin.write(request_line)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise ConnectionError(f"Failed to send request: {e}")

        effective_timeout = timeout if timeout is not None else self.timeout
        response_line = self._read_with_timeout(effective_timeout)

        if not response_line:
            raise ConnectionError("Server closed connection unexpectedly")

        try:
            response = json.loads(response_line)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON response: {e}\nRaw: {response_line[:500]}")

        if "error" in response:
            error = response["error"]
            raise RuntimeError(
                f"MCP error [{error.get('code', -1)}]: {error.get('message', 'Unknown error')}"
            )

        return response.get("result", {})

    def _read_with_timeout(self, timeout: float) -> str:
        """Read a line from stdout with timeout."""
        result = [None]
        error = [None]

        def _read():
            try:
                # Keep reading until we get a valid JSON-RPC line
                while True:
                    line = self._process.stdout.readline()
                    if not line:
                        result[0] = ""
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Check if it looks like JSON-RPC (starts with '{')
                    if line.startswith('{'):
                        result[0] = line
                        break
                    
                    # Skip non-JSON lines (like IDA plugin messages)
                    import sys
                    print(f"[DEBUG] Skipping non-JSON line: {line[:100]}", file=sys.stderr)
                    
            except Exception as e:
                error[0] = e

        thread = threading.Thread(target=_read, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            raise TimeoutError(f"Request timed out after {timeout}s")

        if error[0] is not None:
            raise ConnectionError(f"Failed to read response: {error[0]}")

        return result[0] or ""

    def _send_notification(self, method: str, params: Optional[dict] = None) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }

        notification_line = json.dumps(notification, ensure_ascii=False) + "\n"
        self._process.stdin.write(notification_line)
        self._process.stdin.flush()

    def initialize(self) -> dict:
        """Initialize the MCP connection."""
        result = self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "ida-mcp-pipe-client",
                "version": "0.1.0",
            },
        })
        self._send_notification("notifications/initialized")
        return result

    def list_tools(self) -> list[dict]:
        """List available tools."""
        result = self._send_request("tools/list")
        return result.get("tools", [])

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> Any:
        """Call a tool by name."""
        result = self._send_request("tools/call", {
            "name": name,
            "arguments": arguments or {},
        })

        content = result.get("content", [])
        is_error = result.get("isError", False)

        if content and content[0].get("type") == "text":
            text = content[0]["text"]
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = text

            if is_error:
                error_msg = parsed.get("error", text) if isinstance(parsed, dict) else text
                raise RuntimeError(f"Tool '{name}' error: {error_msg}")
            return parsed

        return content

    def close(self):
        """Close the connection and terminate the server process."""
        try:
            self._process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

        try:
            self._process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def main():
    """Example usage."""
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Connect to a separately running IDA MCP server"
    )
    parser.add_argument(
        "--pipe",
        action="store_true",
        help="Read from stdin/write to stdout (for use with shell pipes)",
    )
    parser.add_argument(
        "--binary",
        type=str,
        help="Binary path (will start server automatically)",
    )
    args = parser.parse_args()

    if args.pipe:
        print("ERROR: Pipe mode not yet implemented in this example", file=sys.stderr)
        print("Use: python -m ida_mcp_stdio binary.so 2>/dev/null | python examples/separate_server_client.py", file=sys.stderr)
        sys.exit(1)

    if not args.binary:
        print("Usage: python examples/connect_to_running_server.py --binary <path>", file=sys.stderr)
        sys.exit(1)

    binary_path = Path(args.binary)
    if not binary_path.exists():
        print(f"Error: Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    # Start server as a separate process
    print(f"Starting server for {binary_path}...", file=sys.stderr)
    command = [sys.executable, "-m", "ida_mcp_stdio", str(binary_path)]

    with PipeBasedMCPClient.connect_to_command(command) as client:
        # Initialize
        info = client.initialize()
        print(f"Connected to: {info['serverInfo']['name']} v{info['serverInfo']['version']}")

        # List tools
        tools = client.list_tools()
        print(f"\nAvailable tools: {len(tools)}")

        # List functions
        print("\nFunctions:")
        funcs = client.call_tool("list_funcs", {"count": 10})
        for func in funcs.get("data", []):
            print(f"  {func['addr']} {func['name']} (size: {func.get('size', '?')})")

        # Decompile first function
        if funcs.get("data"):
            first_func = funcs["data"][0]
            print(f"\nDecompiling {first_func['name']}:")
            try:
                result = client.call_tool("decompile", {"addr": first_func["addr"]})
                if result.get("code"):
                    print(result["code"][:500])
                    if len(result["code"]) > 500:
                        print("... (truncated)")
            except Exception as e:
                print(f"  Error: {e}")

        print("\nDone!")


if __name__ == "__main__":
    main()
