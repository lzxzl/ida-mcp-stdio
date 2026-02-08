#!/usr/bin/env python3
"""Manual tests for memory tools (4 tools).

Tools tested:
9. get_bytes - Read raw bytes from memory
10. get_int - Read an integer value from memory
11. get_string - Read strings from memory
12. get_segment_bytes - Read all bytes from a named segment

Usage:
    python examples/mcp_tools/test_memory_tools.py /path/to/binary
"""

import sys
from pathlib import Path


def test_get_bytes(client):
    """Test 9: get_bytes - Read raw bytes from memory."""
    print("\n" + "="*60)
    print("Test 9: get_bytes")
    print("="*60)
    
    # Get a function address to read from
    funcs = client.list_funcs(count=1)
    if not funcs.get("data"):
        print("❌ No functions found, skipping get_bytes test")
        return
    
    addr = funcs["data"][0]["addr"]
    
    print(f"Reading 32 bytes from {addr}")
    result = client.get_bytes(addr, size=32)
    
    if result.get("error"):
        print(f"❌ Error: {result['error']}")
    elif result.get("data"):
        print(f"✅ Success! Read {result.get('size', 0)} bytes")
        print(f"Data: {result['data'][:50]}...")
    else:
        print("⚠️  No data returned")
    
    # Test different sizes
    print("\nTesting different sizes:")
    for size in [8, 16, 64]:
        result = client.get_bytes(addr, size=size)
        if result.get("data"):
            print(f"  {size} bytes: {result['data'][:30]}...")


def test_get_int(client):
    """Test 10: get_int - Read an integer value from memory."""
    print("\n" + "="*60)
    print("Test 10: get_int")
    print("="*60)
    
    # Get a function address
    funcs = client.list_funcs(count=1)
    if not funcs.get("data"):
        print("❌ No functions found, skipping get_int test")
        return
    
    addr = funcs["data"][0]["addr"]
    
    # Test different integer types
    int_types = [
        ("i8", "8-bit signed"),
        ("u8", "8-bit unsigned"),
        ("i16le", "16-bit signed little-endian"),
        ("i32le", "32-bit signed little-endian"),
        ("i64le", "64-bit signed little-endian"),
        ("u32le", "32-bit unsigned little-endian"),
    ]
    
    print(f"Reading integers from {addr}:")
    for ty, description in int_types:
        result = client.get_int(addr, ty)
        if result.get("error"):
            print(f"  {ty:8s} ({description}): ❌ {result['error']}")
        elif "value" in result:
            print(f"  {ty:8s} ({description}): ✅ {result['value']}")
        else:
            print(f"  {ty:8s} ({description}): ⚠️  No value")


def test_get_string(client):
    """Test 11: get_string - Read strings from memory."""
    print("\n" + "="*60)
    print("Test 11: get_string")
    print("="*60)
    
    # Try to find string addresses
    # First, try imports (they often have string names)
    imports = client.imports(count=5)
    if imports.get("data"):
        addrs = [imp["addr"] for imp in imports["data"][:3]]
        addr_str = ",".join(addrs)
        
        print(f"Reading strings from import addresses:")
        result = client.get_string(addr_str)
        
        if result:
            for item in result:
                if item.get("value"):
                    print(f"  {item['addr']}: ✅ '{item['value']}'")
                elif item.get("error"):
                    print(f"  {item['addr']}: ❌ {item['error']}")
        else:
            print("⚠️  No strings returned")
    else:
        print("⚠️  No imports found to test string reading")
    
    # Try reading from a function address (might not be a string)
    funcs = client.list_funcs(count=1)
    if funcs.get("data"):
        addr = funcs["data"][0]["addr"]
        print(f"\nTrying to read string from function address {addr}:")
        result = client.get_string(addr)
        if result and len(result) > 0:
            if result[0].get("value"):
                print(f"  ✅ '{result[0]['value']}'")
            elif result[0].get("error"):
                print(f"  ⚠️  {result[0]['error']} (expected, not a string)")


def test_get_segment_bytes(client):
    """Test 12: get_segment_bytes - Read all bytes from a named segment."""
    print("\n" + "="*60)
    print("Test 12: get_segment_bytes")
    print("="*60)
    
    # Common segment names
    segments = [".text", ".data", ".rodata", "__TEXT", "__DATA"]
    
    found_segment = False
    for segment in segments:
        print(f"\nTrying to read segment: {segment}")
        try:
            result = client.call_tool("get_segment_bytes", {
                "name": segment,
                "max_size": 1024  # Limit to 1KB for testing
            })
            
            if result.get("error"):
                print(f"  ⚠️  {result['error']}")
            elif result.get("data"):
                print(f"  ✅ Success!")
                print(f"  Start: {result.get('start', 'unknown')}")
                print(f"  End: {result.get('end', 'unknown')}")
                print(f"  Size: {result.get('size', 0)} bytes")
                print(f"  Read: {result.get('read_size', 0)} bytes")
                print(f"  Truncated: {result.get('truncated', False)}")
                print(f"  Data preview: {result['data'][:50]}...")
                found_segment = True
                break
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    if not found_segment:
        print("\n⚠️  No common segments found")


def main():
    if len(sys.argv) < 2:
        print("Usage: python test_memory_tools.py <binary_path>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    if not Path(binary_path).exists():
        print(f"Error: File not found: {binary_path}")
        sys.exit(1)
    
    from ida_mcp_stdio import IDAMCPClient
    
    print("="*60)
    print("MCP Memory Tools Manual Test")
    print("="*60)
    print(f"Binary: {binary_path}")
    
    with IDAMCPClient(binary_path, verbose=False) as client:
        client.initialize()
        
        # Run all tests
        test_get_bytes(client)         # Test 9
        test_get_int(client)           # Test 10
        test_get_string(client)        # Test 11
        test_get_segment_bytes(client) # Test 12
    
    print("\n" + "="*60)
    print("All memory tools tests completed!")
    print("="*60)


if __name__ == "__main__":
    main()
