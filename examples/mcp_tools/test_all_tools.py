#!/usr/bin/env python3
"""Run all MCP tools tests (15 tools total).

This script runs all manual tests for the 15 MCP tools:

Analysis Tools (8):
1. decompile
2. list_funcs
3. disasm
4. xrefs_to
5. callees
6. find_bytes
7. imports
8. list_globals

Memory Tools (4):
9. get_bytes
10. get_int
11. get_string
12. get_segment_bytes

Type Tools (3):
13. search_structs
14. read_struct
15. export_funcs

Usage:
    python examples/mcp_tools/test_all_tools.py /path/to/binary
    
    # With TRACE logging
    python examples/mcp_tools/test_all_tools.py /path/to/binary --trace
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


def setup_logging(enable_trace=False):
    """Setup logging configuration."""
    if enable_trace:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        log_file = log_dir / f"test-all-tools-{timestamp}.log"
        
        logging.basicConfig(
            level=TRACE,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=[
                logging.FileHandler(log_file, encoding="utf-8"),
                logging.StreamHandler(sys.stderr)
            ]
        )
        
        print(f"TRACE logging enabled. Log file: {log_file}", file=sys.stderr)
        return log_file
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        return None


def run_analysis_tests(client):
    """Run all analysis tools tests."""
    from test_analysis_tools import (
        test_decompile, test_list_funcs, test_disasm,
        test_xrefs_to, test_callees, test_find_bytes,
        test_imports, test_list_globals
    )
    
    print("\n" + "="*60)
    print("ANALYSIS TOOLS (8 tools)")
    print("="*60)
    
    test_list_funcs(client)
    test_decompile(client)
    test_disasm(client)
    test_xrefs_to(client)
    test_callees(client)
    test_find_bytes(client)
    test_imports(client)
    test_list_globals(client)


def run_memory_tests(client):
    """Run all memory tools tests."""
    from test_memory_tools import (
        test_get_bytes, test_get_int,
        test_get_string, test_get_segment_bytes
    )
    
    print("\n" + "="*60)
    print("MEMORY TOOLS (4 tools)")
    print("="*60)
    
    test_get_bytes(client)
    test_get_int(client)
    test_get_string(client)
    test_get_segment_bytes(client)


def run_type_tests(client):
    """Run all type tools tests."""
    from test_type_tools import (
        test_search_structs, test_read_struct, test_export_funcs
    )
    
    print("\n" + "="*60)
    print("TYPE TOOLS (3 tools)")
    print("="*60)
    
    test_search_structs(client)
    test_read_struct(client)
    test_export_funcs(client)


def main():
    parser = argparse.ArgumentParser(
        description="Run all MCP tools manual tests (15 tools)"
    )
    parser.add_argument(
        "binary",
        help="Path to binary file to analyze"
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable TRACE level logging"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show server logs"
    )
    
    args = parser.parse_args()
    
    binary_path = args.binary
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}", file=sys.stderr)
        sys.exit(1)
    
    # Setup logging
    log_file = setup_logging(args.trace)
    
    from ida_mcp_stdio import IDAMCPClient
    
    print("="*60)
    print("MCP TOOLS COMPREHENSIVE TEST")
    print("="*60)
    print(f"Binary: {binary_path}")
    print(f"Total tools: 15 (8 analysis + 4 memory + 3 type)")
    print("="*60)
    
    with IDAMCPClient(binary_path, verbose=args.verbose) as client:
        client.initialize()
        
        # Run all test suites
        run_analysis_tests(client)
        run_memory_tests(client)
        run_type_tests(client)
    
    print("\n" + "="*60)
    print("ALL 15 TOOLS TESTED!")
    print("="*60)
    
    if log_file:
        print(f"\nTRACE log saved to: {log_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
