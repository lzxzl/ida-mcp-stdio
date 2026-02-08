#!/usr/bin/env python3
"""Diagnose IDA database status and test basic functionality.

This script helps diagnose why list_funcs might return empty results.

Usage:
    python examples/mcp_tools/diagnose_database.py /path/to/binary
"""

import sys
import time
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print("Usage: python diagnose_database.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)
    
    from ida_mcp_stdio import IDAMCPClient
    
    print("="*60)
    print("IDA Database Diagnosis")
    print("="*60)
    print(f"Binary: {binary_path}\n")
    
    with IDAMCPClient(binary_path, verbose=True) as client:
        print("\n1. Initializing connection...")
        info = client.initialize()
        print(f"   ✅ Connected to: {info['serverInfo']['name']} v{info['serverInfo']['version']}")
        
        print("\n2. Listing available tools...")
        tools = client.list_tools()
        print(f"   ✅ Found {len(tools)} tools")
        
        print("\n3. Testing list_funcs immediately...")
        funcs = client.list_funcs(count=10)
        print(f"   Total functions: {funcs.get('total', 0)}")
        print(f"   Returned: {len(funcs.get('data', []))}")
        
        if not funcs.get("data"):
            print("\n4. Waiting for IDA analysis (10 seconds)...")
            time.sleep(10)
            
            print("\n5. Testing list_funcs again...")
            funcs = client.list_funcs(count=10)
            print(f"   Total functions: {funcs.get('total', 0)}")
            print(f"   Returned: {len(funcs.get('data', []))}")
        
        if funcs.get("data"):
            print(f"   ✅ Functions found!")
            print("\n   First 5 functions:")
            for func in funcs["data"][:5]:
                print(f"     {func['addr']} {func['name']} (size: {func.get('size', '?')})")
        else:
            print(f"   ⚠️  No functions returned")
            
            print("\n5. Trying to get imports instead...")
            imports = client.imports(count=10)
            if imports.get("data"):
                print(f"   ✅ Found {imports.get('total', 0)} imports")
                print("\n   First 5 imports:")
                for imp in imports["data"][:5]:
                    print(f"     {imp['addr']} {imp['name']} (from {imp['module']})")
            else:
                print(f"   ⚠️  No imports found either")
            
            print("\n6. Trying to search for bytes...")
            try:
                # Search for a simple pattern
                result = client.find_bytes("00", limit=5)
                if result and result[0].get("matches"):
                    print(f"   ✅ Found {len(result[0]['matches'])} byte matches")
                    print(f"   First match: {result[0]['matches'][0]}")
                else:
                    print(f"   ⚠️  No byte matches found")
            except Exception as e:
                print(f"   ❌ Error: {e}")
            
            print("\n7. Checking global variables...")
            globals_result = client.list_globals(count=10)
            if globals_result.get("data"):
                print(f"   ✅ Found {globals_result.get('total', 0)} globals")
                print("\n   First 5 globals:")
                for glob in globals_result["data"][:5]:
                    print(f"     {glob['addr']} {glob['name']}")
            else:
                print(f"   ⚠️  No globals found")
        
        print("\n" + "="*60)
        print("Diagnosis Summary:")
        print("="*60)
        
        if funcs.get("data"):
            print("✅ Database is working correctly!")
            print("   Functions are available for analysis.")
        else:
            print("⚠️  Database might not be fully analyzed yet.")
            print("\nPossible reasons:")
            print("1. IDA is still analyzing the binary (wait longer)")
            print("2. Binary has no symbols (stripped binary)")
            print("3. Binary format not fully supported")
            print("4. Database file might be corrupted")
            print("\nSuggestions:")
            print("- Try opening the binary in IDA GUI first")
            print("- Wait for auto-analysis to complete")
            print("- Check if the binary is a valid executable")
            print("- Try with a different binary file")


if __name__ == "__main__":
    main()
