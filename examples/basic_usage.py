#!/usr/bin/env python3
"""Basic usage example for IDA MCP stdio client.

This example demonstrates how to use the Python client to interact
with the IDA MCP server for binary analysis.

Prerequisites:
    - IDA Pro with idalib support installed
    - idapro Python package available

Usage:
    python basic_usage.py /path/to/binary.exe
    python basic_usage.py /path/to/binary.exe --trace
    python basic_usage.py /path/to/binary.exe --log-level DEBUG
"""

import argparse
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


def setup_logging(log_level: str, enable_file: bool = False):
    """Setup logging configuration.
    
    Args:
        log_level: Log level (TRACE, DEBUG, INFO, WARNING, ERROR)
        enable_file: Whether to enable file logging
    """
    # Map log level string to logging constant
    level_map = {
        "TRACE": TRACE,
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    
    level = level_map.get(log_level.upper(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(TRACE)  # Set to lowest level to capture everything
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    console_handler.setFormatter(logging.Formatter(console_format, "%Y-%m-%d %H:%M:%S"))
    root_logger.addHandler(console_handler)
    
    # File handler (if TRACE or explicitly enabled)
    if level == TRACE or enable_file:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = log_dir / f"ida-mcp-client-{timestamp}.log"
        
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(TRACE)
        file_handler.setFormatter(logging.Formatter(console_format, "%Y-%m-%d %H:%M:%S"))
        root_logger.addHandler(file_handler)
        
        print(f"TRACE logging enabled. Log file: {log_file}", file=sys.stderr)
        return log_file
    
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Basic usage example for IDA MCP stdio client"
    )
    parser.add_argument(
        "binary",
        help="Path to binary file to analyze"
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable TRACE level logging (shortcut for --log-level TRACE)"
    )
    parser.add_argument(
        "--log-level",
        choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set log level (default: INFO)"
    )
    parser.add_argument(
        "--log-file",
        action="store_true",
        help="Enable file logging even if not TRACE level"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show server logs (verbose mode)"
    )
    
    args = parser.parse_args()
    
    binary_path = args.binary
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)
    
    # Determine log level
    if args.trace:
        log_level = "TRACE"
    else:
        log_level = args.log_level
    
    # Setup logging
    log_file = setup_logging(log_level, args.log_file)

    from ida_mcp_stdio import IDAMCPClient

    # Use context manager for automatic cleanup
    with IDAMCPClient(binary_path, verbose=args.verbose) as client:
        # Initialize MCP connection
        info = client.initialize()
        print(f"Connected to: {info['serverInfo']['name']} v{info['serverInfo']['version']}")

        # List available tools
        tools = client.list_tools()
        print(f"\nAvailable tools ({len(tools)}):")
        for tool in tools:
            print(f"  - {tool['name']}: {tool['description']}")

        # List functions
        print("\nFunctions:")
        funcs = client.list_funcs(count=10)
        for func in funcs.get("data", []):
            print(f"  {func['addr']} {func['name']} (size: {func.get('size', '?')})")

        if funcs.get("more"):
            print(f"  ... and more (total: {funcs.get('total', '?')})")

        # Decompile a function (try main or first function)
        target = "main"
        if funcs.get("data"):
            first_func = funcs["data"][0]
            target = first_func["addr"]

        print(f"\nDecompiling {target}:")
        result = client.decompile(target)
        if result.get("code"):
            print(result["code"])
        else:
            print(f"  Error: {result.get('error', 'Unknown error')}")

        # Disassemble
        print(f"\nDisassembly of {target}:")
        disasm = client.disasm(target, max_instructions=20)
        for line in disasm.get("lines", []):
            print(f"  {line['addr']}: {line['text']}")
    
    # Print log file location if TRACE was enabled
    if log_file:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"TRACE logging complete!", file=sys.stderr)
        print(f"Check the log file for detailed request/response data:", file=sys.stderr)
        print(f"  {log_file}", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)


if __name__ == "__main__":
    main()
