#!/usr/bin/env python3
"""Manual tests for analysis tools (8 tools).

Tools tested:
1. decompile - Decompile a function to pseudocode
2. list_funcs - List functions in the binary
3. disasm - Disassemble instructions
4. xrefs_to - Get cross-references
5. callees - Get functions called by specified functions
6. find_bytes - Search for byte patterns
7. imports - List imported symbols
8. list_globals - List global variables

Usage:
    python examples/mcp_tools/test_analysis_tools.py /path/to/binary
"""

import sys
from pathlib import Path


def test_decompile(client):
    """Test 1: decompile - Decompile a function to pseudocode."""
    print("\n" + "="*60)
    print("Test 1: decompile")
    print("="*60)
    
    # First get a function address
    funcs = client.list_funcs(count=1)
    if not funcs.get("data"):
        print("❌ No functions found, skipping decompile test")
        return
    
    addr = funcs["data"][0]["addr"]
    name = funcs["data"][0]["name"]
    
    print(f"Decompiling function: {name} at {addr}")
    result = client.decompile(addr)
    
    if result.get("error"):
        print(f"❌ Error: {result['error']}")
    elif result.get("code"):
        print(f"✅ Success! Code length: {len(result['code'])} chars")
        print(f"First 200 chars:\n{result['code'][:200]}")
    else:
        print("⚠️  No code returned")


def test_list_funcs(client):
    """Test 2: list_funcs - List functions in the binary."""
    print("\n" + "="*60)
    print("Test 2: list_funcs")
    print("="*60)
    
    # Test basic listing
    print("\n2.1 Basic listing (first 5 functions):")
    funcs = client.list_funcs(count=5)
    print(f"Total functions: {funcs.get('total', 0)}")
    print(f"Returned: {len(funcs.get('data', []))}")
    print(f"More available: {funcs.get('more', False)}")
    
    for func in funcs.get("data", []):
        print(f"  {func['addr']} {func['name']} (size: {func.get('size', '?')})")
    
    if funcs.get("data"):
        print("✅ list_funcs works!")
    else:
        print("⚠️  No functions returned")
    
    # Test filtering
    print("\n2.2 Filtering (functions starting with 'sub_'):")
    filtered = client.list_funcs(filter="sub_*", count=5)
    print(f"Filtered results: {len(filtered.get('data', []))}")
    for func in filtered.get("data", [])[:3]:
        print(f"  {func['addr']} {func['name']}")
    
    # Test pagination
    print("\n2.3 Pagination (offset=5, count=5):")
    paginated = client.list_funcs(offset=5, count=5)
    print(f"Returned: {len(paginated.get('data', []))}")
    for func in paginated.get("data", [])[:3]:
        print(f"  {func['addr']} {func['name']}")


def test_disasm(client):
    """Test 3: disasm - Disassemble instructions."""
    print("\n" + "="*60)
    print("Test 3: disasm")
    print("="*60)
    
    # Get a function address
    funcs = client.list_funcs(count=1)
    if not funcs.get("data"):
        print("❌ No functions found, skipping disasm test")
        return
    
    addr = funcs["data"][0]["addr"]
    name = funcs["data"][0]["name"]
    
    print(f"Disassembling function: {name} at {addr}")
    result = client.disasm(addr, max_instructions=10)
    
    if result.get("error"):
        print(f"❌ Error: {result['error']}")
    elif result.get("lines"):
        print(f"✅ Success! Disassembled {len(result['lines'])} instructions")
        for line in result["lines"][:5]:
            print(f"  {line['addr']}: {line['text']}")
        if len(result["lines"]) > 5:
            print(f"  ... and {len(result['lines']) - 5} more")
    else:
        print("⚠️  No disassembly returned")


def test_xrefs_to(client):
    """Test 4: xrefs_to - Get cross-references."""
    print("\n" + "="*60)
    print("Test 4: xrefs_to")
    print("="*60)
    
    # Get a function address
    funcs = client.list_funcs(count=3)
    if not funcs.get("data"):
        print("❌ No functions found, skipping xrefs_to test")
        return
    
    # Try to find a function that might have xrefs
    addr = funcs["data"][0]["addr"]
    name = funcs["data"][0]["name"]
    
    print(f"Getting xrefs to: {name} at {addr}")
    result = client.xrefs_to(addr, limit=10)
    
    if result and len(result) > 0:
        xrefs = result[0].get("xrefs", [])
        if xrefs:
            print(f"✅ Found {len(xrefs)} cross-references")
            for xref in xrefs[:3]:
                fn_info = xref.get("fn", {})
                fn_name = fn_info.get("name", "unknown") if fn_info else "unknown"
                print(f"  {xref['addr']} ({xref['type']}) from {fn_name}")
            if len(xrefs) > 3:
                print(f"  ... and {len(xrefs) - 3} more")
        else:
            print("⚠️  No cross-references found")
    else:
        print("⚠️  No results returned")


def test_callees(client):
    """Test 5: callees - Get functions called by specified functions."""
    print("\n" + "="*60)
    print("Test 5: callees")
    print("="*60)
    
    # Get a function address
    funcs = client.list_funcs(count=1)
    if not funcs.get("data"):
        print("❌ No functions found, skipping callees test")
        return
    
    addr = funcs["data"][0]["addr"]
    name = funcs["data"][0]["name"]
    
    print(f"Getting callees of: {name} at {addr}")
    result = client.callees(addr, limit=10)
    
    if result and len(result) > 0:
        callees = result[0].get("callees", [])
        if callees:
            print(f"✅ Found {len(callees)} called functions")
            for callee in callees[:5]:
                print(f"  {callee['addr']} {callee['name']} ({callee['type']})")
            if len(callees) > 5:
                print(f"  ... and {len(callees) - 5} more")
        else:
            print("⚠️  No called functions found")
    else:
        print("⚠️  No results returned")


def test_find_bytes(client):
    """Test 6: find_bytes - Search for byte patterns."""
    print("\n" + "="*60)
    print("Test 6: find_bytes")
    print("="*60)
    
    # Common patterns to search for
    patterns = [
        ("55 48 89 E5", "Function prologue (x64)"),
        ("48 8B ?? ??", "MOV instruction with wildcards"),
        ("C3", "RET instruction"),
    ]
    
    for pattern, description in patterns:
        print(f"\nSearching for: {pattern} ({description})")
        try:
            result = client.find_bytes(pattern, limit=5)
            
            if result and len(result) > 0:
                matches = result[0].get("matches", [])
                if matches:
                    print(f"✅ Found {len(matches)} matches")
                    for match in matches[:3]:
                        print(f"  {match}")
                    if len(matches) > 3:
                        print(f"  ... and {len(matches) - 3} more")
                    break  # Found something, stop searching
                else:
                    print("⚠️  No matches found")
            else:
                print("⚠️  No results returned")
        except TimeoutError:
            print(f"⚠️  Search timed out (pattern might be too common)")
        except Exception as e:
            print(f"❌ Error: {e}")


def test_imports(client):
    """Test 7: imports - List imported symbols."""
    print("\n" + "="*60)
    print("Test 7: imports")
    print("="*60)
    
    print("Getting imported symbols...")
    result = client.imports(count=10)
    
    if result.get("data"):
        print(f"✅ Found {result.get('total', 0)} imports")
        print(f"Showing first {len(result['data'])}:")
        for imp in result["data"][:5]:
            print(f"  {imp['addr']} {imp['name']} (from {imp['module']})")
        if len(result["data"]) > 5:
            print(f"  ... and {len(result['data']) - 5} more")
    else:
        print("⚠️  No imports found")


def test_list_globals(client):
    """Test 8: list_globals - List global variables."""
    print("\n" + "="*60)
    print("Test 8: list_globals")
    print("="*60)
    
    print("Getting global variables...")
    result = client.list_globals(count=10)
    
    if result.get("data"):
        print(f"✅ Found {result.get('total', 0)} globals")
        print(f"Showing first {len(result['data'])}:")
        for glob in result["data"][:5]:
            print(f"  {glob['addr']} {glob['name']}")
        if len(result["data"]) > 5:
            print(f"  ... and {len(result['data']) - 5} more")
    else:
        print("⚠️  No global variables found")


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_analysis_tools.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)
    
    from ida_mcp_stdio import IDAMCPClient
    
    print("="*60)
    print("MCP Analysis Tools Manual Test")
    print("="*60)
    print(f"Binary: {binary_path}")
    
    with IDAMCPClient(binary_path, verbose=False) as client:
        client.initialize()
        
        # Run all tests
        test_list_funcs(client)      # Test 2 first (needed by others)
        #test_decompile(client)        # Test 1
        test_disasm(client)           # Test 3
        test_xrefs_to(client)         # Test 4
        test_callees(client)          # Test 5
        test_find_bytes(client)       # Test 6
        test_imports(client)          # Test 7
        test_list_globals(client)     # Test 8
    
    print("\n" + "="*60)
    print("All analysis tools tests completed!")
    print("="*60)


if __name__ == "__main__":
    main()
