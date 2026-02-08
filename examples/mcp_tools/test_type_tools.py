#!/usr/bin/env python3
"""Manual tests for type tools (3 tools).

Tools tested:
13. search_structs - Search for structure types by name
14. read_struct - Read struct type definition and parse memory values
15. export_funcs - Export function information in various formats

Usage:
    python examples/mcp_tools/test_type_tools.py /path/to/binary
"""

import sys
from pathlib import Path


def test_search_structs(client):
    """Test 13: search_structs - Search for structure types by name."""
    print("\n" + "="*60)
    print("Test 13: search_structs")
    print("="*60)
    
    # Common structure names to search for
    search_terms = ["FILE", "stat", "sockaddr", "timeval", "iovec"]
    
    found_any = False
    for term in search_terms:
        print(f"\nSearching for structures containing '{term}':")
        result = client.search_structs(term)
        
        if result and len(result) > 0:
            print(f"  ✅ Found {len(result)} structures")
            for struct in result[:3]:
                print(f"    - {struct['name']} (size: {struct['size']}, "
                      f"members: {struct.get('cardinality', '?')}, "
                      f"union: {struct.get('is_union', False)})")
            if len(result) > 3:
                print(f"    ... and {len(result) - 3} more")
            found_any = True
            break
        else:
            print(f"  ⚠️  No structures found")
    
    if not found_any:
        print("\n⚠️  No common structures found in this binary")


def test_read_struct(client):
    """Test 14: read_struct - Read struct type definition and parse memory values."""
    print("\n" + "="*60)
    print("Test 14: read_struct")
    print("="*60)
    
    # First, search for a structure
    search_terms = ["FILE", "stat", "sockaddr"]
    struct_name = None
    
    for term in search_terms:
        result = client.search_structs(term)
        if result and len(result) > 0:
            struct_name = result[0]["name"]
            print(f"Found structure: {struct_name}")
            break
    
    if not struct_name:
        print("⚠️  No structures found, skipping read_struct test")
        return
    
    # Get a function address to use as memory location
    funcs = client.list_funcs(count=1)
    if not funcs.get("data"):
        print("❌ No functions found, skipping read_struct test")
        return
    
    addr = funcs["data"][0]["addr"]
    
    print(f"\nReading structure '{struct_name}' at {addr}:")
    result = client.read_struct(addr, struct=struct_name)
    
    if result.get("error"):
        print(f"  ⚠️  {result['error']} (expected if address doesn't contain this struct)")
    elif result.get("members"):
        print(f"  ✅ Success! Structure has {len(result['members'])} members")
        print(f"  Structure: {result.get('struct', 'unknown')}")
        print(f"  Members:")
        for member in result["members"][:5]:
            print(f"    +{member['offset']}: {member['type']:20s} {member['name']:15s} "
                  f"= {member.get('value', 'N/A')}")
        if len(result["members"]) > 5:
            print(f"    ... and {len(result['members']) - 5} more members")
    else:
        print("  ⚠️  No members returned")
    
    # Test auto-detection (without specifying struct name)
    print(f"\nTrying auto-detection at {addr}:")
    result = client.read_struct(addr)
    if result.get("struct"):
        print(f"  ✅ Auto-detected structure: {result['struct']}")
    elif result.get("error"):
        print(f"  ⚠️  {result['error']}")


def test_export_funcs(client):
    """Test 15: export_funcs - Export function information in various formats."""
    print("\n" + "="*60)
    print("Test 15: export_funcs")
    print("="*60)
    
    # Get some function addresses
    funcs = client.list_funcs(count=3)
    if not funcs.get("data"):
        print("❌ No functions found, skipping export_funcs test")
        return
    
    addrs = [func["addr"] for func in funcs["data"]]
    addr_str = ",".join(addrs)
    
    # Test different export formats
    formats = ["json", "c_header", "prototypes"]
    
    for fmt in formats:
        print(f"\n15.{formats.index(fmt) + 1} Export format: {fmt}")
        result = client.export_funcs(addr_str, format=fmt)
        
        if result and len(result) > 0:
            print(f"  ✅ Exported {len(result)} functions")
            
            if fmt == "json":
                # Show detailed JSON info
                for func in result[:2]:
                    print(f"    Function: {func.get('name', 'unknown')}")
                    print(f"      Address: {func.get('addr', 'unknown')}")
                    print(f"      Size: {func.get('size', 'unknown')}")
                    prototype = func.get('prototype')
                    if prototype:
                        print(f"      Prototype: {prototype[:60]}...")
                    else:
                        print(f"      Prototype: N/A")
                    if func.get('code'):
                        print(f"      Code length: {len(func['code'])} chars")
            
            elif fmt == "c_header":
                # Show C header output
                for func in result[:2]:
                    if isinstance(func, dict) and func.get('prototype'):
                        print(f"    {func['prototype']};")
                    elif isinstance(func, str):
                        print(f"    {func[:80]}...")
            
            elif fmt == "prototypes":
                # Show prototypes
                for func in result[:2]:
                    if isinstance(func, dict) and func.get('prototype'):
                        print(f"    {func['prototype']}")
                    elif isinstance(func, str):
                        print(f"    {func[:80]}...")
            
            if len(result) > 2:
                print(f"    ... and {len(result) - 2} more")
        else:
            print(f"  ⚠️  No results returned")


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_type_tools.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)
    
    from ida_mcp_stdio import IDAMCPClient
    
    print("="*60)
    print("MCP Type Tools Manual Test")
    print("="*60)
    print(f"Binary: {binary_path}")
    
    with IDAMCPClient(binary_path, verbose=False) as client:
        client.initialize()
        
        # Run all tests
        test_search_structs(client)  # Test 13
        test_read_struct(client)     # Test 14
        test_export_funcs(client)    # Test 15
    
    print("\n" + "="*60)
    print("All type tools tests completed!")
    print("="*60)


if __name__ == "__main__":
    main()
