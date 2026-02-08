#!/usr/bin/env python3
"""Decompile a specific function by name or address.

Usage:
    # By function name
    python examples/mcp_tools/decompile_function.py binary.so main
    python examples/mcp_tools/decompile_function.py binary.so _Z17bte_load_did_confPKc
    
    # By address
    python examples/mcp_tools/decompile_function.py binary.so 0x401000
    
    # List all functions first
    python examples/mcp_tools/decompile_function.py binary.so --list
    
    # Search for functions by pattern
    python examples/mcp_tools/decompile_function.py binary.so --search "bte_*"
"""

import argparse
import sys
from pathlib import Path


def list_functions(client, filter_pattern="", count=50):
    """List functions in the binary."""
    print(f"\nListing functions (filter: '{filter_pattern or 'none'}'):")
    print("="*60)
    
    funcs = client.list_funcs(filter=filter_pattern, count=count)
    
    if not funcs.get("data"):
        print("⚠️  No functions found")
        print("\nTrying to get imports instead...")
        imports = client.imports(count=count)
        if imports.get("data"):
            print(f"\nFound {imports.get('total', 0)} imports:")
            for imp in imports["data"]:
                print(f"  {imp['addr']} {imp['name']} (from {imp['module']})")
        return
    
    print(f"Total functions: {funcs.get('total', 0)}")
    print(f"Showing: {len(funcs['data'])}\n")
    
    for func in funcs["data"]:
        print(f"  {func['addr']:12s} {func['name']:40s} (size: {func.get('size', '?')})")
    
    if funcs.get("more"):
        print(f"\n... and more (use --count to see more)")


def decompile_function(client, target):
    """Decompile a function by name or address."""
    print(f"\nDecompiling: {target}")
    print("="*60)
    
    try:
        result = client.decompile(target)
        
        if result.get("error"):
            print(f"❌ Error: {result['error']}")
            
            # Try to find similar function names
            print(f"\nSearching for similar function names...")
            funcs = client.list_funcs(filter=f"*{target}*", count=10)
            if funcs.get("data"):
                print(f"Found {len(funcs['data'])} similar functions:")
                for func in funcs["data"]:
                    print(f"  {func['addr']} {func['name']}")
                print("\nTry one of these addresses or names instead.")
            else:
                print("No similar functions found.")
            
            return False
        
        if result.get("code"):
            print(f"✅ Success!\n")
            print(f"Function: {result.get('addr', target)}")
            print(f"Code length: {len(result['code'])} characters")
            print("\nDecompiled code:")
            print("-"*60)
            print(result["code"])
            print("-"*60)
            return True
        else:
            print("⚠️  No code returned")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False


def disassemble_function(client, target, max_instructions=50):
    """Disassemble a function as fallback."""
    print(f"\nDisassembling: {target}")
    print("="*60)
    
    try:
        result = client.disasm(target, max_instructions=max_instructions)
        
        if result.get("error"):
            print(f"❌ Error: {result['error']}")
            return False
        
        if result.get("lines"):
            print(f"✅ Success!\n")
            print(f"Function: {result.get('function', target)}")
            print(f"Instructions: {len(result['lines'])}")
            print("\nDisassembly:")
            print("-"*60)
            for line in result["lines"]:
                print(f"  {line['addr']:12s} {line['text']}")
            print("-"*60)
            return True
        else:
            print("⚠️  No disassembly returned")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Decompile a specific function by name or address",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decompile by function name
  python decompile_function.py binary.so main
  python decompile_function.py binary.so _Z17bte_load_did_confPKc
  
  # Decompile by address
  python decompile_function.py binary.so 0x401000
  
  # List all functions
  python decompile_function.py binary.so --list
  
  # Search for functions
  python decompile_function.py binary.so --search "bte_*"
  
  # Decompile with disassembly fallback
  python decompile_function.py binary.so main --disasm
        """
    )
    
    parser.add_argument(
        "binary",
        help="Path to binary file"
    )
    parser.add_argument(
        "function",
        nargs="?",
        help="Function name or address to decompile"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all functions"
    )
    parser.add_argument(
        "--search",
        metavar="PATTERN",
        help="Search for functions matching pattern (glob)"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Number of functions to list (default: 50)"
    )
    parser.add_argument(
        "--disasm",
        action="store_true",
        help="Also show disassembly"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show server logs"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.list and not args.search and not args.function:
        parser.error("Either provide a function name/address, or use --list or --search")
    
    binary_path = args.binary
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)
    
    from ida_mcp_stdio import IDAMCPClient
    
    print("="*60)
    print("Function Decompiler")
    print("="*60)
    print(f"Binary: {binary_path}")
    
    with IDAMCPClient(binary_path, verbose=args.verbose) as client:
        client.initialize()
        
        # List mode
        if args.list:
            list_functions(client, count=args.count)
            return
        
        # Search mode
        if args.search:
            list_functions(client, filter_pattern=args.search, count=args.count)
            return
        
        # Decompile mode
        if args.function:
            success = decompile_function(client, args.function)
            
            if not success or args.disasm:
                print("\n" + "="*60)
                disassemble_function(client, args.function)
    
    print("\n" + "="*60)
    print("Done!")
    print("="*60)


if __name__ == "__main__":
    main()
