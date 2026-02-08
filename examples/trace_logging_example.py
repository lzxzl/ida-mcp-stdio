#!/usr/bin/env python3
"""Example demonstrating TRACE level logging for detailed request/response inspection.

This example shows how to enable TRACE logging to see full JSON-RPC
request and response content, which is useful for:
- Debugging communication issues
- Understanding the protocol
- Monitoring data flow
- Performance analysis

Usage:
    python examples/trace_logging_example.py /path/to/binary.exe
    
The TRACE logs will be written to logs/ida-mcp-YYYYMMDD-HHMMSS.log
"""

import logging
import sys
from datetime import datetime
from pathlib import Path


# Define TRACE level
TRACE = 5
logging.addLevelName(TRACE, "TRACE")

def trace(self, message, *args, **kwargs):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kwargs)

logging.Logger.trace = trace


def setup_trace_logging():
    """Setup TRACE level logging to both console and file."""
    # Create logs directory
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Generate log filename
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = log_dir / f"ida-mcp-client-{timestamp}.log"
    
    # Configure logging
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(TRACE)
    
    # Console handler (INFO level)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(log_format, date_format))
    root_logger.addHandler(console_handler)
    
    # File handler (TRACE level)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(TRACE)
    file_handler.setFormatter(logging.Formatter(log_format, date_format))
    root_logger.addHandler(file_handler)
    
    print(f"TRACE logging enabled. Log file: {log_file}", file=sys.stderr)
    return log_file


def main():
    if len(sys.argv) < 2:
        print("Usage: python trace_logging_example.py <binary_path>")
        sys.exit(1)

    binary_path = sys.argv[1]
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)

    # Setup TRACE logging
    log_file = setup_trace_logging()

    from ida_mcp_stdio import IDAMCPClient

    # Start server with TRACE logging
    # Note: Server needs to be started with --log-level TRACE separately
    # or we can pass it via server_script parameter
    print("\nStarting IDA MCP client with TRACE logging...", file=sys.stderr)
    print("Server logs will be in logs/ida-mcp-*.log", file=sys.stderr)
    print(f"Client logs will be in {log_file}\n", file=sys.stderr)

    with IDAMCPClient(binary_path, verbose=True) as client:
        # Initialize
        print("Initializing connection...", file=sys.stderr)
        info = client.initialize()
        print(f"Connected to: {info['serverInfo']['name']} v{info['serverInfo']['version']}\n")

        # List tools
        print("Listing tools...", file=sys.stderr)
        tools = client.list_tools()
        print(f"Available tools: {len(tools)}\n")

        # List functions
        print("Listing functions...", file=sys.stderr)
        funcs = client.list_funcs(count=3)
        print(f"Functions (showing {len(funcs['data'])} of {funcs['total']}):")
        for func in funcs["data"]:
            print(f"  {func['addr']} {func['name']}")

        # Decompile first function
        if funcs["data"]:
            first_func = funcs["data"][0]
            print(f"\nDecompiling {first_func['name']}...", file=sys.stderr)
            result = client.decompile(first_func["addr"])
            if result.get("code"):
                print(f"\nDecompiled code (first 200 chars):")
                print(result["code"][:200])
                if len(result["code"]) > 200:
                    print("...")

        # Disassemble
        if funcs["data"]:
            first_func = funcs["data"][0]
            print(f"\nDisassembling {first_func['name']}...", file=sys.stderr)
            disasm = client.disasm(first_func["addr"], max_instructions=5)
            print(f"\nDisassembly (first 5 instructions):")
            for line in disasm["lines"]:
                print(f"  {line['addr']}: {line['text']}")

    print(f"\n{'='*60}")
    print(f"TRACE logging complete!")
    print(f"Check the log file for detailed request/response data:")
    print(f"  {log_file}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
