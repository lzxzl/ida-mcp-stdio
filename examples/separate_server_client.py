#!/usr/bin/env python3
"""Example of using a separately running server process.

This demonstrates how to connect to an already-running IDA MCP server
instead of having the client automatically start one.

Usage:
    # Terminal 1: Start the server manually
    python -m ida_mcp_stdio so/libbluetooth.so --verbose

    # Terminal 2: Run this client
    python examples/separate_server_client.py
"""

import json
import sys
import threading
from typing import Any, Optional


class ExternalMCPClient:
    """Client that connects to an external MCP server via stdin/stdout.
    
    This client reads from stdin and writes to stdout, expecting the
    server to be on the other end of these pipes (e.g., when launched
    via shell pipe or IDE integration).
    """

    def __init__(self, timeout: float = 300):
        """Initialize client for external server communication.
        
        Args:
            timeout: Default request timeout in seconds.
        """
        self.timeout = timeout
        self._request_id = 0

    def _next_id(self) -> int:
        """Get the next request ID."""
        self._request_id += 1
        return self._request_id

    def _send_request(
        self,
        method: str,
        params: Optional[dict] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """Send a JSON-RPC request and return the result.
        
        Args:
            method: JSON-RPC method name.
            params: Method parameters.
            timeout: Request timeout in seconds.
            
        Returns:
            The result field from the response.
        """
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
            "id": self._next_id(),
        }

        # Write to stdout (server's stdin)
        request_line = json.dumps(request, ensure_ascii=False) + "\n"
        sys.stdout.write(request_line)
        sys.stdout.flush()

        # Read from stdin (server's stdout) with timeout
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
        """Read a line from stdin with timeout."""
        result = [None]
        error = [None]

        def _read():
            try:
                # Keep reading until we get a valid JSON-RPC line
                while True:
                    line = sys.stdin.readline()
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
        sys.stdout.write(notification_line)
        sys.stdout.flush()

    # MCP protocol methods

    def initialize(self) -> dict:
        """Initialize the MCP connection."""
        result = self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "ida-mcp-external-client",
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


def main():
    """Example usage of external client.
    
    This expects to be piped to/from a running server:
        python -m ida_mcp_stdio binary.so | python examples/separate_server_client.py
    """
    # Redirect stderr for logging (since stdout/stdin are used for protocol)
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="[CLIENT] %(message)s",
        stream=sys.stderr,
    )
    logger = logging.getLogger(__name__)

    try:
        client = ExternalMCPClient()

        # Initialize connection
        logger.info("Initializing connection...")
        info = client.initialize()
        logger.info(f"Connected to: {info['serverInfo']['name']} v{info['serverInfo']['version']}")

        # List tools
        tools = client.list_tools()
        logger.info(f"Available tools: {len(tools)}")

        # List functions
        logger.info("Listing functions...")
        funcs = client.call_tool("list_funcs", {"count": 5})
        for func in funcs.get("data", []):
            logger.info(f"  {func['addr']} {func['name']}")

        # Try to decompile first function
        if funcs.get("data"):
            first_func = funcs["data"][0]
            logger.info(f"Decompiling {first_func['name']}...")
            result = client.call_tool("decompile", {"addr": first_func["addr"]})
            if result.get("code"):
                logger.info(f"Decompiled code:\n{result['code'][:200]}...")

        logger.info("Done!")

    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
